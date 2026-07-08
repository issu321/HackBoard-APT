"""
HackBoard Example Plugin
========================

This is a sample plugin demonstrating the plugin architecture.
Copy this file and modify it to create your own plugins.
"""

PLUGIN_NAME = "Example Plugin"
PLUGIN_VERSION = "1.0.0"
PLUGIN_DESCRIPTION = "A sample plugin for HackBoard demonstrating the plugin interface."


def register(app_context: dict) -> None:
    """Register the plugin with the HackBoard application.

    Args:
        app_context: Dictionary containing application context.
    """
    print(f"[PLUGIN] {PLUGIN_NAME} v{PLUGIN_VERSION} loaded")
    # Add your plugin logic here
