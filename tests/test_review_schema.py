import json
import unittest
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "review.schema.json"


def _objects(node, path="$"):
    if isinstance(node, dict):
        if isinstance(node.get("properties"), dict):
            yield path, node
        for key, value in node.items():
            yield from _objects(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _objects(value, f"{path}[{index}]")


class ReviewSchemaStrictModeTests(unittest.TestCase):
    def test_every_object_lists_all_properties_as_required(self):
        """Codex strict schema mode rejects any object whose `required` omits a property;
        an optional field silently breaks every delegate/codex review run."""
        schema = json.loads(SCHEMA.read_text())
        self.assertEqual("object", schema.get("type"))
        self.assertEqual({"verdict", "summary", "findings", "declared_changes_assessed", "verification_token", "reviewed_files"},
                         set(schema.get("properties", {})))
        self.assertEqual({"reviewed", "pass", "partial", "fail"}, set(schema["properties"]["verdict"]["enum"]))
        self.assertEqual(12, schema["properties"]["findings"]["maxItems"])
        objects = list(_objects(schema))
        self.assertEqual({"$", "$.properties.findings.items", "$.properties.declared_changes_assessed.items"},
                         {path for path, _ in objects})
        for path, node in objects:
            self.assertIs(node.get("additionalProperties"), False, path)
            self.assertEqual(
                sorted(node["properties"]),
                sorted(node.get("required", [])),
                f"{path}: required must list every property exactly",
            )
