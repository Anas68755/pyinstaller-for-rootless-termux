import { defineConfig } from "vite";
import basicSsl from "@vitejs/plugin-basic-ssl";

// HTTPS is required here, not optional: both getUserMedia (camera) and
// WebXR require a "secure context". When testing on a phone over your
// LAN (not localhost), the browser will only allow either if the page is
// served over https. This plugin generates a local self-signed cert -
// Chrome will show a warning the first time, which you can safely accept
// on your own network.
export default defineConfig({
  plugins: [basicSsl()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    https: true
  }
});
