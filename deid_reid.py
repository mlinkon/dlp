"""Uses of the Data Loss Prevention API for deidentifying sensitive data."""

# Import the client library
import argparse
import google.cloud
import google.cloud.dlp
import google.api
from datetime import datetime

def print_hello_world():
    print(str(datetime.now)+ " : Hello World test")
    return " : Hello World test"
    
# [START dlp_deidentify_cdc]
def deidentify_with_cdc(
    project,
    info_types,
    surrogate_type,
    key_name,
    wrapped_key,
    data_items,
    data_headers,
    alphabet=None,

):
    """Uses the Data Loss Prevention API to deidentify sensitive data in a
    string using Format Preserving Encryption (FPE).
    Args:
        project: The Google Cloud project id to use as a parent resource.
        item: The string to deidentify (will be treated as text).
        alphabet: The set of characters to replace sensitive ones with. For
            more information, see https://cloud.google.com/dlp/docs/reference/
            rest/v2beta2/organizations.deidentifyTemplates#ffxcommonnativealphabet
        surrogate_type: The name of the surrogate custom info type to use. Only
            necessary if you want to reverse the deidentification process. Can
            be essentially any arbitrary string, as long as it doesn't appear
            in your dataset otherwise.
        key_name: The name of the Cloud KMS key used to encrypt ('wrap') the
            AES-256 key. Example:
            key_name = 'projects/YOUR_GCLOUD_PROJECT/locations/YOUR_LOCATION/
            keyRings/YOUR_KEYRING_NAME/cryptoKeys/YOUR_KEY_NAME'
        wrapped_key: The encrypted ('wrapped') AES-256 key to use. This key
            should be encrypted using the Cloud KMS key specified by key_name.
    Returns:
        None; the response from the API is printed to the terminal.
    """
    
    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # The wrapped key is base64-encoded, but the library expects a binary
    # string, so decode it here.
    import base64

    wrapped_key = base64.b64decode(wrapped_key)

    # Construct CyrptoDeterministicConfig configuration dictionary
    crypto_deterministic_config = {
        "crypto_key": {
            "kms_wrapped": {
                "wrapped_key": wrapped_key,
                "crypto_key_name": key_name,
            }
        }
    }

    # Add surrogate type
    if surrogate_type:
        crypto_deterministic_config["surrogate_info_type"] = {
            "name": surrogate_type
        }

    # Construct inspect configuration dictionary
    inspect_config = {
        "info_types": [{"name": info_type} for info_type in info_types],
        "min_likelihood": "POSSIBLE"
    }

    # Construct deidentify configuration dictionary
    deidentify_config = {
        "info_type_transformations": {
            "transformations": [
                {
                    "primitive_transformation": {
                        "crypto_deterministic_config": crypto_deterministic_config
                    }
                }
            ]
        }
    }

    # Construct the table dict
    table_item = {
        "table": {
            "headers": [{"name": header} for header in data_headers], 
            "rows": [{"values": [{"string_value": key}, {"string_value": value}]} for key, value in data_items.items()]
        }
    }

    # Call the API
    response = dlp.deidentify_content(
        parent,
        inspect_config=inspect_config,
        deidentify_config=deidentify_config,
        item=table_item,
    )

    return response.item.table

# [END dlp_deidentify_fpe]
