// MCP smoke test: spawn the server over stdio, list tools, call detect_sensitive.
// Run: npx tsx mcp/smoke.ts
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

const transport = new StdioClientTransport({ command: 'npx', args: ['tsx', 'mcp/server.ts'] })
const client = new Client({ name: 'smoke', version: '0' })
await client.connect(transport)

const { tools } = await client.listTools()
console.log('TOOLS:', tools.map((t) => t.name).join(', '))

// Secret-shaped but synthetic; built from fragments so no literal pattern is committed.
const FAKE_LEAKED_KEY = 'sk-' + 'proj-' + '1a2b3c4d5e6f7g8h9i0jklmnop'

const res: any = await client.callTool({
  name: 'detect_sensitive',
  arguments: { text: `rotate this leaked key ${FAKE_LEAKED_KEY}` },
})
console.log('detect_sensitive →', res.content?.[0]?.text)

// Set MCP_PAID=1 to run a real paid private_inference against the configured server.
if (process.env.MCP_PAID) {
  const inf: any = await client.callTool({
    name: 'private_inference',
    arguments: { prompt: `A service leaked ${FAKE_LEAKED_KEY}. One-line rotation step?` },
  })
  const t = inf.content?.[0]?.text ?? ''
  console.log('private_inference → isError:', !!inf.isError, '| len:', t.length, '| tail:', t.slice(-90).replace(/\n/g, ' '))
}

await client.close()
console.log('OK')
