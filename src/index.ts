import { ClientOptions, Cloudflare } from 'cloudflare';

class HttpError extends Error {
	constructor(
		public statusCode: number,
		message: string,
	) {
		super(message);
		this.name = 'HttpError';
	}
}

function constructClientOptions(request: Request): ClientOptions {
	const authorization = request.headers.get('Authorization');
	if (!authorization) {
		throw new HttpError(401, 'API token missing.');
	}

	const [, data] = authorization.split(' ');
	const decoded = atob(data);
	const index = decoded.indexOf(':');

	if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
		throw new HttpError(401, 'Invalid API key or token.');
	}

	return {
		apiEmail: decoded.substring(0, index),
		apiToken: decoded.substring(index + 1),
	};
}

function constructIPPolicy(request: Request): IPPolicy {
	const url = new URL(request.url);
	const params = url.searchParams;
	const ip = params.get('ip');
	const policyKey = params.get('hostname');

	if (ip === null || ip === undefined) {
		throw new HttpError(422, 'The "ip" parameter is required and cannot be empty.');
	}

	if (policyKey === null || policyKey === undefined) {
		throw new HttpError(422, 'The "hostname" parameter is required and cannot be empty.');
	}

	return {
		content: ip,
		name: policyKey
	};
}

async function update(clientOptions: ClientOptions, newPolicy: IPPolicy): Promise<Response> {
	const cloudflare = new Cloudflare(clientOptions);

	const tokenStatus = (await cloudflare.user.tokens.verify()).status;
	if (tokenStatus !== 'active') {
		throw new HttpError(401, 'This API Token is ' + tokenStatus);
	}

	// Get KV namespace.
	const namespaces = (await cloudflare.kv.namespaces.list({account_id: clientOptions.apiEmail})).result;
	if (namespaces.length == 0) {
		throw new HttpError(400, 'No KV namespaces found!');
	}

	// Get specific namespace.
	const nsTitle = 'unifi-cloudflare-ddns-access-kv';  // TODO:derived from wrangler.toml:name
	let nsId = undefined;
	for(let i = 0; i < namespaces.length; i++) {
		if (namespaces[i].title == nsTitle) {
			nsId = namespaces[i].id;
			break;
		}
	}
	if (nsId === undefined) {
		throw new HttpError(400, 'Unable to locate KV namespace with title ' + nsTitle + '.');
	}

	console.log('before policyUUID');
	// Get policy noted by hostname input.
	const policyUUID = await cloudflare.kv.namespaces.values.get(nsId, newPolicy.name, {account_id: clientOptions.apiEmail});
	if (!policyUUID) {
		throw new HttpError(400, 'No policy found! You must first manually create the policy.');
	}
	console.log('before policyResponse');
	// Fetch existing policy
	const policyResponse = await cloudflare.zeroTrust.access.policies.update(policyUUID, {account_id: clientOptions.apiEmail});
	if (!policyResponse.ok) {
		throw new HttpError(400, 'Failed to fetch access policy.');
	}
	console.log('before policyData');
	const policyData = await policyResopnse.json();

	// Modify the IP rule in the policy
	let updates = false;
	const newRules = policyData.result.rules.map((rule: any) => {
		if (rule.include && Array.isArray(rule.include)) {
			rule.include = rule.include.map((includeRule: any) => {
				if (includeRule.ip) {
					includeRule.ip = [newPolicy.content]; // Replace with the new IP
					updated = true;
				}
				return includeRule;
			});
		}
		return rule;
	});

	if (!updated) {
		throw new HttpError(400, 'No IP rule found to update in the policy.');
	}

	// Send updated policy
	const updateResponse = await cloudflare.zeroTrust.access.policies.update(policyUUID, {rules: newRules, account_id: clientOptions.apiEmail});
	if (!updateResponse.ok) {
		throw new HttpError(400, 'Failed ot update access policy.')
	}

	console.log('Policy ' + newPolicy.name + ' updated successfully to ' + newPolicy.content);

	return new Response('OK', { status: 200 });
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		console.log('Requester IP: ' + request.headers.get('CF-Connecting-IP'));
		console.log(request.method + ': ' + request.url);
		console.log('Body: ' + (await request.text()));

		try {
			// Construct client options and IP policy
			const clientOptions = constructClientOptions(request);
			const policy = constructIPPolicy(request);

			// Run the update function
			return await update(clientOptions, policy);
		} catch (error) {
			if (error instanceof HttpError) {
				console.log('Error updating policy: ' + error.message);
				return new Response(error.message, { status: error.statusCode });
			} else {
				console.log('Error updating policy: ' + error);
				return new Response('Internal Server Error', { status: 500 });
			}
		}
	},
} satisfies ExportedHandler<Env>;
