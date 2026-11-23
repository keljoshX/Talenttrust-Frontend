import { describe, expect, it, vi } from 'vitest';
import * as http from 'node:http';
import {
  createPinnedLookup,
  defaultHttpClient,
  validateWebhookUrl,
  type ResolvedAddress,
  type WebhookResolver,
} from './webhooks';

const publicResolver = vi.fn(async (hostname: string): Promise<ResolvedAddress[]> => {
  if (hostname !== 'hooks.example') throw new Error('unexpected host');
  return [{ address: '93.184.216.34', family: 4 }];
});

describe('validateWebhookUrl', () => {
  it('accepts public hosts and returns the validated addresses', async () => {
    const validated = await validateWebhookUrl('https://hooks.example/hook', publicResolver);

    expect(validated.hostname).toBe('hooks.example');
    expect(validated.addresses).toEqual(['93.184.216.34']);
  });

  it('rejects private addresses returned by an injected resolver', async () => {
    const resolver: WebhookResolver = async () => [{ address: '10.0.0.8', family: 4 }];

    await expect(validateWebhookUrl('https://hooks.example/hook', resolver)).rejects.toThrow(/private|prohibited/i);
  });

  it('uses only pinned addresses in the injected lookup', async () => {
    const validated = await validateWebhookUrl('https://hooks.example/hook', publicResolver);
    const lookup = createPinnedLookup(validated);
    const callback = vi.fn();

    lookup('hooks.example', { all: true, family: 0 }, callback);

    expect(callback).toHaveBeenCalledWith(
      null,
      [{ address: '93.184.216.34', family: 4 }],
      undefined,
    );
  });

  it('passes the original hostname to HTTP Host while using the pinned lookup', async () => {
    const transport = {
      request: vi.fn((options: http.RequestOptions, callback?: (response: http.IncomingMessage) => void) => {
        expect(options.hostname).toBe('hooks.example');
        expect((options.headers as http.OutgoingHttpHeaders)?.Host).toBe('hooks.example');
        expect(options.lookup).toBeTypeOf('function');

        const handlers = new Map<string, (...args: unknown[]) => void>();
        const response = {
          statusCode: 204,
          headers: {},
          on: vi.fn((event: string, handler: (...args: unknown[]) => void) => {
            handlers.set(event, handler);
            return response;
          }),
          resume: vi.fn(),
          destroy: vi.fn(),
        } as unknown as http.IncomingMessage;
        callback?.(response);
        queueMicrotask(() => handlers.get('end')?.());

        return {
          on: vi.fn().mockReturnThis(),
          write: vi.fn(),
          end: vi.fn(),
          destroy: vi.fn(),
        } as unknown as http.ClientRequest;
      }),
    } as unknown as typeof http;

    const result = await defaultHttpClient('http://hooks.example/hook', {
      resolver: publicResolver,
      transport,
    });

    expect(result.statusCode).toBe(204);
  });

  it('rejects redirects instead of following them', async () => {
    const transport = {
      request: vi.fn((options: http.RequestOptions, callback?: (response: http.IncomingMessage) => void) => {
        const response = {
          statusCode: 302,
          headers: { location: 'https://internal.example/path' },
          resume: vi.fn(),
          on: vi.fn().mockReturnThis(),
          destroy: vi.fn(),
        } as unknown as http.IncomingMessage;
        callback?.(response);

        return {
          on: vi.fn().mockReturnThis(),
          write: vi.fn(),
          end: vi.fn(),
          destroy: vi.fn(),
        } as unknown as http.ClientRequest;
      }),
    } as unknown as typeof http;

    const result = await defaultHttpClient('http://hooks.example/hook', {
      resolver: publicResolver,
      transport,
      method: 'POST',
    });

    expect(result.redirected).toBe(true);
    expect(result.statusCode).toBe(302);
    expect(transport.request).toHaveBeenCalledTimes(1);
  });

  it('pins the public address instead of allowing a private rebinding lookup', async () => {
    const resolver: WebhookResolver = vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]);
    const transport = {
      request: vi.fn((options: http.RequestOptions, callback?: (response: http.IncomingMessage) => void) => {
        expect(options.lookup).toBeTypeOf('function');
        const lookup = options.lookup as NonNullable<http.RequestOptions['lookup']>;
        const lookupCallback = vi.fn();
        lookup('hooks.example', { all: true, family: 0 }, lookupCallback);
        expect(lookupCallback).toHaveBeenCalledWith(null, [{ address: '93.184.216.34', family: 4 }], undefined);

        const handlers = new Map<string, (...args: unknown[]) => void>();
        const response = {
          statusCode: 204,
          headers: {},
          on: vi.fn((event: string, handler: (...args: unknown[]) => void) => {
            handlers.set(event, handler);
            return response;
          }),
          resume: vi.fn(),
          destroy: vi.fn(),
        } as unknown as http.IncomingMessage;
        callback?.(response);
        queueMicrotask(() => handlers.get('end')?.());

        return {
          on: vi.fn().mockReturnThis(),
          write: vi.fn(),
          end: vi.fn(),
          destroy: vi.fn(),
        } as unknown as http.ClientRequest;
      }),
    } as unknown as typeof http;

    await defaultHttpClient('http://hooks.example/hook', { resolver, transport });
    expect(resolver).toHaveBeenCalledTimes(1);
  });
});
