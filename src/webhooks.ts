import * as dns from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';

export const WEBHOOK_TIMEOUT_MS = 5_000;
export const WEBHOOK_MAX_RESPONSE_BYTES = 64 * 1024;

export type ResolvedAddress = {
  address: string;
  family: 4 | 6;
};

export type WebhookResolver =
  | ((hostname: string) => Promise<ResolvedAddress[] | string[]> | ResolvedAddress[] | string[])
  | ((
      hostname: string,
      options: dns.LookupAllOptions,
      callback: (error: NodeJS.ErrnoException | null, addresses: ResolvedAddress[]) => void,
    ) => void);

export type WebhookLookup = (
  hostname: string,
  options: dns.LookupOptions | number,
  callback: (
    error: NodeJS.ErrnoException | null,
    address: string | ResolvedAddress[],
    family?: number,
  ) => void,
) => void;

export class ValidatedWebhookUrl extends URL {
  readonly addresses: readonly string[];
  readonly resolvedAddresses: readonly ResolvedAddress[];

  constructor(url: URL, addresses: readonly ResolvedAddress[]) {
    super(url.toString());
    this.resolvedAddresses = Object.freeze(addresses.map((entry) => ({ ...entry })));
    this.addresses = Object.freeze(addresses.map((entry) => entry.address));
  }

  /** Backwards-compatible alias for callers that treat validation as URL + address data. */
  get url(): URL {
    return this;
  }
}

export interface WebhookResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  redirected: boolean;
}

export interface WebhookRequestOptions {
  method?: string;
  headers?: http.OutgoingHttpHeaders;
  body?: string | Buffer | Uint8Array;
  timeoutMs?: number;
  maxResponseBytes?: number;
  resolver?: WebhookResolver;
  transport?: typeof http | typeof https;
}

function isPrivateAddress(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) {
    const parts = address.split('.').map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return true;
    }
    const [a, b, c] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }

  if (family === 6) {
    const normalized = address.toLowerCase().split('%')[0];
    if (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb') ||
      normalized.startsWith('ff')
    ) {
      return true;
    }
    const ipv4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (ipv4Mapped) return isPrivateAddress(ipv4Mapped[1]);
    return false;
  }

  return true;
}

function normalizeResolvedAddresses(value: unknown): ResolvedAddress[] {
  const entries = Array.isArray(value) ? value : [];
  const addresses: ResolvedAddress[] = [];

  for (const entry of entries) {
    if (typeof entry === 'string') {
      const family = net.isIP(entry);
      if (family === 4 || family === 6) addresses.push({ address: entry, family });
    } else if (
      typeof entry === 'object' &&
      entry !== null &&
      'address' in entry &&
      typeof (entry as { address?: unknown }).address === 'string'
    ) {
      const record = entry as { address: string; family?: number };
      const family = net.isIP(record.address);
      if (family === 4 || family === 6) addresses.push({ address: record.address, family });
    }
  }

  return addresses;
}

async function resolveWebhookHost(hostname: string, resolver: WebhookResolver): Promise<ResolvedAddress[]> {
  const resolverFunction = resolver as (...args: unknown[]) => unknown;

  if (resolverFunction.length >= 3) {
    return await new Promise<ResolvedAddress[]>((resolve, reject) => {
      resolverFunction(hostname, { all: true, verbatim: true }, (error: NodeJS.ErrnoException | null, value: unknown) => {
        if (error) reject(error);
        else resolve(normalizeResolvedAddresses(value));
      });
    });
  }

  const value = await resolverFunction(hostname);
  return normalizeResolvedAddresses(value);
}

const defaultResolver: WebhookResolver = async (hostname: string) => {
  return await dns.promises.lookup(hostname, { all: true, verbatim: true });
};

export async function validateWebhookUrl(
  input: string | URL,
  resolver: WebhookResolver = defaultResolver,
): Promise<ValidatedWebhookUrl> {
  let url: URL;
  try {
    url = input instanceof URL ? new URL(input.toString()) : new URL(input);
  } catch {
    throw new Error('Invalid webhook URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Webhook URL must use HTTP or HTTPS');
  }
  if (!url.hostname) throw new Error('Webhook URL must include a hostname');
  if (url.username || url.password) throw new Error('Webhook URL must not contain credentials');

  let addresses: ResolvedAddress[];
  const validationHostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;
  const literalFamily = net.isIP(validationHostname);
  if (literalFamily === 4 || literalFamily === 6) {
    addresses = [{ address: validationHostname, family: literalFamily }];
  } else {
    addresses = await resolveWebhookHost(validationHostname, resolver);
  }

  if (addresses.length === 0) throw new Error(`Unable to resolve webhook host: ${url.hostname}`);

  for (const entry of addresses) {
    if (isPrivateAddress(entry.address)) {
      throw new Error(`Webhook host resolves to a private or prohibited address: ${entry.address}`);
    }
  }

  return new ValidatedWebhookUrl(url, addresses);
}

export function createPinnedLookup(validated: ValidatedWebhookUrl): WebhookLookup {
  const pinned = validated.resolvedAddresses;

  return (_hostname, options, callback) => {
    const requestedFamily = typeof options === 'number' ? options : options?.family;
    let matches = pinned.filter((entry) => !requestedFamily || requestedFamily === 0 || entry.family === requestedFamily);
    if (matches.length === 0) matches = [...pinned];

    const all = typeof options === 'object' && options !== null && options.all === true;
    if (all) {
      callback(null, matches.map((entry) => ({ address: entry.address, family: entry.family })), undefined);
      return;
    }

    const selected = matches[0];
    callback(null, selected.address, selected.family);
  };
}

export type HttpClient = (
  url: ValidatedWebhookUrl | URL | string,
  bodyOrOptions?: string | Buffer | Uint8Array | WebhookRequestOptions,
  maybeOptions?: WebhookRequestOptions,
) => Promise<WebhookResponse>;

export const defaultHttpClient: HttpClient = async (
  input,
  bodyOrOptions,
  maybeOptions,
) => {
  const options: WebhookRequestOptions =
    typeof bodyOrOptions === 'object' && !(bodyOrOptions instanceof Uint8Array) && !(bodyOrOptions instanceof Buffer)
      ? { ...bodyOrOptions, ...maybeOptions }
      : { ...maybeOptions, body: bodyOrOptions as string | Buffer | Uint8Array | undefined };

  let validated: ValidatedWebhookUrl;
  if (input instanceof ValidatedWebhookUrl) {
    validated = await validateWebhookUrl(input.toString(), options.resolver);
  } else {
    validated = await validateWebhookUrl(input.toString(), options.resolver);
  }

  const method = (options.method ?? 'POST').toUpperCase();
  const timeoutMs = options.timeoutMs ?? WEBHOOK_TIMEOUT_MS;
  const maxResponseBytes = options.maxResponseBytes ?? WEBHOOK_MAX_RESPONSE_BYTES;
  const body = options.body;

  const transport = options.transport ?? (validated.protocol === 'https:' ? https : http);

  return await new Promise<WebhookResponse>((resolve, reject) => {
    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(overallTimer);
      callback();
    };

    const timeoutError = () => {
      const error = new Error('Webhook request timed out');
      (error as NodeJS.ErrnoException).code = 'ETIMEDOUT';
      return error;
    };

    const overallTimer = setTimeout(() => {
      finish(() => req.destroy(timeoutError()));
    }, timeoutMs);

    const safeHeaders: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(options.headers ?? {})) {
      if (key.toLowerCase() !== 'host') safeHeaders[key] = value;
    }

    const requestOptions: http.RequestOptions | https.RequestOptions = {
      protocol: validated.protocol,
      hostname: validated.hostname,
      port: validated.port || undefined,
      servername: validated.protocol === 'https:' ? validated.hostname : undefined,
      path: `${validated.pathname}${validated.search}`,
      method,
      headers: {
        ...safeHeaders,
        Host: validated.host,
        ...(body !== undefined && !Object.keys(safeHeaders).some((key) => key.toLowerCase() === 'content-length')
          ? { 'content-length': Buffer.byteLength(body) }
          : {}),
      },
      lookup: createPinnedLookup(validated) as unknown as NonNullable<http.RequestOptions['lookup']>,
      // The redirect response is returned, never followed.
      timeout: 0,
    };

    const req = transport.request(requestOptions, (response) => {
      if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        finish(() => resolve({
          statusCode: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.alloc(0),
          redirected: true,
        }));
        return;
      }

      const chunks: Buffer[] = [];
      let bytes = 0;

      response.on('data', (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (bytes + buffer.length > maxResponseBytes) {
          req.destroy(new Error(`Webhook response exceeded ${maxResponseBytes} bytes`));
          response.destroy();
          return;
        }
        bytes += buffer.length;
        chunks.push(buffer);
      });
      response.on('end', () => {
        finish(() => resolve({
          statusCode: response.statusCode ?? 0,
          headers: response.headers,
          body: Buffer.concat(chunks),
          redirected: false,
        }));
      });
      response.on('error', (error) => {
        finish(() => reject(error));
      });
    });

    req.on('socket', (socket) => {
      socket.setTimeout(timeoutMs, () => {
        req.destroy(timeoutError());
      });
    });
    req.on('error', (error) => {
      finish(() => reject(error));
    });

    if (body !== undefined) req.write(body);
    req.end();
  });
};

export const sendWebhook = defaultHttpClient;
