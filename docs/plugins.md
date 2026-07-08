# Plugin Development Guide

## Creating a Plugin

Create a Python file in `hackboard/plugins/`:

```python
# plugins/my_plugin.py

PLUGIN_NAME = "My Security Plugin"
PLUGIN_VERSION = "1.0.0"
PLUGIN_DESCRIPTION = "Custom security analysis for HackBoard"


def register(app_context: dict) -> None:
    """Called when HackBoard loads the plugin."""
    print(f"[PLUGIN] {PLUGIN_NAME} loaded successfully")

    # Access app context
    # app_context contains session state and configuration
```

## Plugin Discovery

Plugins are automatically discovered on startup. No registration needed.

## Best Practices

- Use descriptive PLUGIN_NAME
- Handle exceptions gracefully
- Log using `hackboard.utils.logger`
- Follow PEP 8 style guidelines
