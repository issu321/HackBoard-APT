"""
HackBoard — Plugin System
===========================

Plugins placed in this directory are automatically discovered and loaded.
Each plugin should be a valid Python module.

Plugin Interface:
    - Optional: PLUGIN_NAME (str): Human-readable plugin name.
    - Optional: PLUGIN_VERSION (str): Plugin version.
    - Optional: PLUGIN_DESCRIPTION (str): Brief description.
    - Optional: register(app): Function called with the Streamlit app context.
"""
