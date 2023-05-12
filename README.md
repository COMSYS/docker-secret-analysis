# Code to our Internet-wide Study on Secrets in Docker Images

## Description

This repository contains core code we used to find secrets, i.e., private keys and API secrets, in Docker container images. Specifically, we publish our code to enable open-source secret scanners, e.g., TruffleHog, to integrate parts or ideas of it.

If you use any portion of our work, please cite our paper:

```
@inproceedings{2023-dahlmanns-docker,
    author = {Dahlmanns, Markus and Sander, Constantin and Decker, Robin and Wehrle, Klaus},
    title = {Secrets Revealed in Container Images: An Internet-wide Study on Occurrence and Impact},
    booktitle = {Proceedings of the 2023 ACM on Asia Conference on Computer and Communications Security},
    doi = {10.1145/3579856.3590329},
    isbn = {979-8-4007-0098-9/23/07},
    year = {2023},
}
```

## Countermeasures

Our code cannot be used to scan own images for secrets conveniently as it was designed to perform secret scanning on images at scale. Instead, other (closed-source) software promises to do so:

- Deepfence SecretScanner (<https://github.com/deepfence/SecretScanner>)
- GitGuardian ggshield (<https://github.com/GitGuardian/ggshield>)

**Disclaimer:** Note that we do not have influence on these projects and how they perform their secret scanning. Some approaches might upload the image content to the services for scanning. Also, we did not evaluate how well they perform.

## Repository Content

The content of this repository splits in two tools: *docker-analyzer* and *validation*. Both folders contain more detailed README files.

### docker-analyzer

The folder docker-analyzer includes our image scanning tool. It takes information on new image layers that should be analyzed from AMQP, downloads, and analyzes the layers as well as creates a folder structure containing meta information on each layer and found matches.

### validation

The folder validation contains our Jupyter Notebook to validate matches of the docker-analyzer and further analyze information from Dockerfiles.