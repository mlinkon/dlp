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
