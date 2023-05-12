# docker-analyzer

This tool allows the matching of regular expressions on each file included in any Docker image layer. To this end, the tool connects via AMQP to a broker and awaits messages with information on layers to scan.

It subsequently starts to download the image and match regular expressions given in `signatures/signatures.yaml` on each file. Each match is stored with accompanying meta data for later analysis.