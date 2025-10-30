#!/usr/bin/env python3
# Test pre-commit hooks

import sys
import yaml


def check_secret(data, filename):
    """Check if a YAML/JSON document contains unencrypted sensitive data.

    This checks:
    1. Kubernetes Secret resources
    2. Raw JSON/YAML files with data/stringData fields that should be encrypted
    3. Secret generator configurations referencing secret files
    4. Kustomize patches containing unencrypted secrets
    5. SecretManagerSecretVersion resources with spec.secretData.value
    """
    if not isinstance(data, dict):
        return True

    # Check for secret generator configurations
    if data.get("kind") == "ksops" and data.get("apiVersion", "").startswith(
        "viaduct.ai/"
    ):
        # For ksops generators, we don't need to encrypt the generator itself
        # The referenced files will be checked separately
        return True

    # Check for kustomize secretGenerator
    if data.get("kind") == "Kustomization":
        # Check secretGenerator
        if "secretGenerator" in data:
            for generator in data["secretGenerator"]:
                # Always fail on unencrypted literals
                if "literals" in generator:
                    print("Unencrypted literals found in secretGenerator")
                    print("Please use SOPS or KSOPS to encrypt secrets")
                    return False
                # Check for unencrypted files
                if "files" in generator:
                    for file in generator["files"]:
                        if not (
                            file.endswith(".enc.yaml") or file.endswith(".sops.yaml")
                        ):
                            print("Unencrypted file reference in secretGenerator")
                            print("Use encrypted files (*.enc.yaml or *.sops.yaml)")
                            return False

        # Check patches for unencrypted secrets
        if "patches" in data:
            for patch in data["patches"]:
                if isinstance(patch, dict) and "patch" in patch:
                    try:
                        patch_data = yaml.safe_load(patch["patch"])
                        if isinstance(patch_data, dict):
                            if patch_data.get("kind") == "Secret":
                                if not check_secret(patch_data, filename):
                                    print("Unencrypted secret found in kustomize patch")
                                    return False
                    except yaml.YAMLError:
                        # If we can't parse the patch, skip it
                        pass
        return True

    # Check for SecretManagerSecretVersion resources (Google Cloud Config Connector)
    if data.get("kind") == "SecretManagerSecretVersion":
        # Check if it has secretData.value under spec (valueFrom doesn't need encryption)
        spec = data.get("spec", {})
        secret_data = spec.get("secretData", {})
        if isinstance(secret_data, dict) and "value" in secret_data:
            # spec.secretData.value contains the actual secret and needs to be encrypted
            if "sops" not in data:
                print(f"Unencrypted SecretManagerSecretVersion found in {filename}")
                print("SecretManagerSecretVersion resources with spec.secretData.value must be encrypted")
                print("Please encrypt data using SOPS before committing")
                return False
            return validate_sops_metadata(data, filename)
        # If it only has spec.secretData.valueFrom or no secretData, it doesn't need encryption
        return True

    # For Kubernetes resources, only check Secrets
    if "kind" in data:
        if data["kind"] != "Secret":
            return True

    # For non-Kubernetes files, check if they contain sensitive data fields
    has_data = "data" in data
    has_string_data = "stringData" in data

    # Skip if no data fields present
    if not (has_data or has_string_data):
        # If this is a Secret with SOPS metadata, validate it even without data
        if data.get("kind") == "Secret" and "sops" in data:
            return validate_sops_metadata(data, filename)
        return True

    # Check if this is a SOPS encrypted file
    if "sops" in data:
        return validate_sops_metadata(data, filename)

    # If not encrypted, check for non-empty data
    data_value = data.get("data")
    string_data_value = data.get("stringData")
    secret_data_value = data.get("secretData")

    # For dict values, check if any values are non-empty
    if isinstance(data_value, dict):
        has_data = any(v for v in data_value.values() if v is not None and v != "")
    else:
        has_data = data_value is not None and data_value != ""

    if isinstance(string_data_value, dict):
        has_string_data = any(
            v for v in string_data_value.values() if v is not None and v != ""
        )
    else:
        has_string_data = string_data_value is not None and string_data_value != ""

    if isinstance(secret_data_value, dict):
        has_secret_data = any(
            v for v in secret_data_value.values() if v is not None and v != ""
        )
    else:
        has_secret_data = secret_data_value is not None and secret_data_value != ""

    if has_data or has_string_data or has_secret_data:
        print(f"Unencrypted sensitive data found in {filename}")
        print("Please encrypt data using SOPS before committing")
        return False

    return True


def validate_sops_metadata(data, filename):
    """Validate that SOPS metadata is present and valid."""
    if not isinstance(data.get("sops"), dict):
        print(f"Invalid SOPS metadata structure in {filename}")
        return False

    sops_data = data["sops"]
    if (
        "mac" not in sops_data
        or "lastmodified" not in sops_data
        or sops_data.get("mac") is None
        or sops_data.get("lastmodified") is None
    ):
        print(f"Missing or invalid required SOPS metadata fields in {filename}")
        return False

    return True


def check_template_content(content, filename):
    """Check template files for sensitive patterns without parsing.

    This checks for unencrypted values after common secret keys.
    Private keys and certificates are handled by detect-private-keys hook.

    Lines can be ignored by adding '# sops-pre-commit: ignore-line' comment.
    """
    # Skip empty content
    if not content or not content.strip():
        return True

    # Common keys that might contain sensitive data
    sensitive_keys = ["password:", "token:", "secret:", "key:", "cert:", "data:"]

    # Check for secrets after common keys
    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Check for sensitive data after common secret keys
        if any(key in line.lower() for key in sensitive_keys):
            # Skip if line has ignore comment
            if "# sops-pre-commit: ignore-line" in line:
                continue

            # Get the value part after the key
            value = line.split(":", 1)[1].strip() if ":" in line else ""

            # Skip empty values, template variables, or encrypted values
            if (
                not value
                or value.startswith(("{{", "{%", "${", "$("))
                or "ENC[" in value
            ):
                continue

            print(f"Unencrypted secret found in template {filename}")
            print("Please encrypt data using SOPS before committing")
            print("To ignore this line, add '# sops-pre-commit: ignore-line' comment")
            return False

    return True


def extract_yaml_documents(content):
    """Extract potential YAML documents from any text content.

    This handles:
    1. Full YAML files
    2. YAML blocks inside debug output
    3. kubectl/kustomize output redirected to files

    Note: We only care about finding secrets, not validating YAML syntax
    """
    documents = []
    current_doc = []
    in_yaml = False

    for line in content.splitlines():
        # Start of potential YAML block
        if line.strip() == "---" or line.strip().startswith("apiVersion:"):
            if current_doc and in_yaml:
                try:
                    doc = yaml.safe_load("\n".join(current_doc))
                    if doc:
                        documents.append(doc)
                except yaml.YAMLError:
                    pass  # We don't care about malformed YAML, only secrets
            current_doc = []
            in_yaml = True
            current_doc.append(line)
            continue

        # Inside a potential YAML block
        if in_yaml:
            # End of YAML-like content
            if not line.strip() or line.strip().startswith(("DEBUG:", "Command:", "#")):
                try:
                    doc = yaml.safe_load("\n".join(current_doc))
                    if doc:
                        documents.append(doc)
                except yaml.YAMLError:
                    pass  # We don't care about malformed YAML, only secrets
                current_doc = []
                in_yaml = False
            else:
                current_doc.append(line)
        # Look for start of YAML block
        elif line.strip().startswith(("apiVersion:", "kind:", "metadata:")):
            in_yaml = True
            current_doc.append(line)

    # Handle last document
    if current_doc and in_yaml:
        try:
            doc = yaml.safe_load("\n".join(current_doc))
            if doc:
                documents.append(doc)
        except yaml.YAMLError:
            pass  # We don't care about malformed YAML, only secrets

    return documents


def main():
    """Main entry point."""
    exit_code = 0

    for filename in sys.argv[1:]:
        try:
            with open(filename, "r") as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file {filename}: {e}")
            exit_code = 1
            continue

        # Check for file-level ignore comment at the start
        first_lines = content.splitlines()[:3]  # Check first 3 lines for comment
        if any("# sops-pre-commit: ignore-file" in line for line in first_lines):
            continue

        # Handle template files separately
        if filename.endswith((".j2", ".jsonnet")):
            if not check_template_content(content, filename):
                exit_code = 1
                continue

        try:
            # Try both YAML parsing methods, ignoring YAML errors
            docs = []
            try:
                docs = list(yaml.safe_load_all(content))
            except yaml.YAMLError:
                docs = extract_yaml_documents(content)

            # Check each document for secrets
            for doc in docs:
                if doc and not check_secret(doc, filename):
                    exit_code = 1
                    break

        except Exception as e:
            print(f"Unexpected error processing {filename}: {e}")
            exit_code = 1
            continue

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
