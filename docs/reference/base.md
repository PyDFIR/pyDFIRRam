## Base

The `Generic` hierarchy discovers plugins through **`PluginRegistry`**, caching the catalogue **once per (Volatility version, OS)**. Prefer **`run_plugin`**, **`list_plugins`**, **`has_plugin`**, and **`plugin_info`** for stable callers; legacy attribute access is deprecated. See the **[Plugins (SDK API)](../tutorials/plugins-sdk.md)** tutorial.

::: pydfirram.core.base