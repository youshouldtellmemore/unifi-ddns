import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Cloudflare } from 'cloudflare';

// Mock functions
const mockVerify = vi.fn();
const mockListZones = vi.fn();
const mockListRecords = vi.fn();
const mockUpdateRecord = vi.fn();

vi.mock('cloudflare', () => {
	return {
		Cloudflare: vi.fn().mockImplementation(() => ({
			user: {
				tokens: {
					verify: mockVerify,
				},
			},
			zones: {
				list: mockListZones,
			},
			dns: {
				records: {
					list: mockListRecords,
					update: mockUpdateRecord,
				},
			},
		})),
	};
});

describe('UniFi DDNS Worker', () => {
	beforeEach(() => {
		// Clear all mocks before each test to prevent state leakage
		vi.clearAllMocks();
	});

	it('responds with 401 when API token is missing', async () => {
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com');
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('API token missing.');
	});

	it('responds with 401 when API token is invalid', async () => {
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				// CodeQL [js/hardcoded-credentials] Suppressing hardcoded credential warning for test
				Authorization: 'Basic invalidtoken',
			},
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API key or token.');
	});

	it('responds with 401 when token is not active', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'inactive' });

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('This API Token is inactive');
	});

	it('responds with 422 when IP is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		const response = await SELF.fetch('http://example.com/update?hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(422);
		expect(await response.text()).toBe('The "ip" parameter is required and cannot be empty.');
	});

	it('responds with 422 when hostname is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(422);
		expect(await response.text()).toBe('The "hostname" parameter is required and cannot be empty.');
	});
});
