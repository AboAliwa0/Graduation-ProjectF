from core.plugin_loader import PluginLoader
from plugins.clickjacking import ClickjackingScanner

loader = PluginLoader()

loader.register(ClickjackingScanner())

result = loader.run(
    "clickjacking",
    "https://example.com"
)

print("=" * 50)
print("Plugin:", result.plugin_name)
print("Target:", result.target)
print("Vulnerable:", result.vulnerable)
print("Severity:", result.severity)
print("Confidence:", result.confidence)
print("Title:", result.title)
print("Description:", result.description)
print("Recommendation:", result.recommendation)
print("Evidence:", result.evidence)
print("Status Code:", result.status_code)
print("Execution Time:", result.execution_time)
print("=" * 50)