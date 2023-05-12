# Validation

This Jupyter Notebook validates our matches for later analysis. To this end, it reads information on the matches from a Database and generates a Pickle file containing required data.

To validate our matches for later analysis, this Jupyter Notebook requires the data of the docker-analyzer to be imported in SQL tables of the following format:

#### matches

|#|Column Name|Data Type|Description|
|:----|:----|:----|:----|
|1|registry|String|Registry where we found the match.|
|2|repository|String|Repository where we found the match.|
|3|file_sha256|String|SHA256 sum of the complete file where we found the match in.|
|4|file_name|String|Path of the file where we found the match in.|
|5|rule|String|Rule / Regular expression name that matched.|
|6|data|String|Data that was matched.|
|7|match_sha256|String|SHA256 sum of the match.|
|8|layer|String|Layer where we found the match in.|

#### matchrule_group

|#|Column Name|Data Type|Description|
|:----|:----|:----|:----|
|1|name|String|Name of the rule.|
|2|group|String|Group of the rule.|

#### match_findings

|#|Column Name|Data Type|Description|
|:----|:----|:----|:----|
|1|match_sha256|String|SHA256 sum of the match.|
|2|type|String|Type of the finding, e.g., private key.|
|3|findingRaw|String|Data of the finding.|
|4|fingerprint|String|Fingerprint of the finding.|
|5|corrFingerprint|String|Corresponding fingerprint of the finding, e.g., the fingerprint of a corresponding public key of a private key.|

#### imageconfigs_envval

|#|Column Name|Data Type|Description|
|:----|:----|:----|:----|
|1|registry|String|Registry where we found the variable in.|
|2|repository|String|Repository where we found the variable in.|
|3|env_val|String|Name of the variable.|
|4|env_var|String|Value of the variable.|
