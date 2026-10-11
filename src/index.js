/**
 * @dmsdc-ai/telesession — core API (no dependencies). The MCP adapter is a separate entry
 * (`@dmsdc-ai/telesession/mcp`) so core consumers never load MCP or zod.
 */

export { ConfigError, loadConfig, normalizeConfig } from "./config.js";
export { StoreError } from "./store.js";
export {
  REQUIRED_CAPABILITIES, createTeleptyTransport, parseReplyNonce, classifyAuditRows, mapReceipt,
} from "./transports/telepty.js";
