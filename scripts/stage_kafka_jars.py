#!/usr/bin/env python3
"""Stage the Spark-Kafka connector jars in object storage for AIDP jobs.

The AIDP Spark image ships Iceberg, hadoop-aws and aws-java-sdk-bundle, but no
Kafka connector, so `format("kafka")` fails with "Failed to find data source:
kafka". The jars also cannot travel with `--file-upload` (kafka-clients is
4.9 MB, and the CLI caps uploads at 1 MB per file), so they are placed in the
bucket and referenced as `--jars s3a://.../*.jar`; Spark downloads them at
startup using the image's hadoop-aws.

Versions are pinned to the image: Spark 3.5.7 / Scala 2.12. kafka-clients and
commons-pool2 versions come from the spark-sql-kafka-0-10 POM, not guesswork.

Usage (needs internet for Maven, plus S3 credentials):
    S3_ACCESS_KEY=... S3_SECRET_KEY=... ./scripts/stage_kafka_jars.py
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import urllib.request

import boto3
from botocore.config import Config

SPARK_VERSION = os.environ.get("SPARK_VERSION", "3.5.7")
SCALA_VERSION = os.environ.get("SCALA_VERSION", "2.12")
KAFKA_CLIENTS_VERSION = os.environ.get("KAFKA_CLIENTS_VERSION", "3.4.1")
COMMONS_POOL2_VERSION = os.environ.get("COMMONS_POOL2_VERSION", "2.11.1")

MAVEN = os.environ.get("MAVEN_REPO", "https://repo1.maven.org/maven2")
BUCKET = os.environ.get("S3_BUCKET", "js-demo")
PREFIX = os.environ.get("S3_JARS_PREFIX", "jars")
ENDPOINT = os.environ.get("S3_ENDPOINT", "http://172.18.11.31:9020")

ARTIFACTS = [
    ("org.apache.spark", f"spark-sql-kafka-0-10_{SCALA_VERSION}", SPARK_VERSION),
    ("org.apache.spark", f"spark-token-provider-kafka-0-10_{SCALA_VERSION}", SPARK_VERSION),
    ("org.apache.kafka", "kafka-clients", KAFKA_CLIENTS_VERSION),
    ("org.apache.commons", "commons-pool2", COMMONS_POOL2_VERSION),
]


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def main() -> int:
    access_key = os.environ.get("S3_ACCESS_KEY")
    secret_key = os.environ.get("S3_SECRET_KEY")
    if not (access_key and secret_key):
        sys.exit("Set S3_ACCESS_KEY and S3_SECRET_KEY")

    s3 = boto3.client(
        "s3", endpoint_url=ENDPOINT,
        aws_access_key_id=access_key, aws_secret_access_key=secret_key,
        config=Config(s3={"addressing_style": "path"}),
    )

    with tempfile.TemporaryDirectory() as workdir:
        for group, artifact, version in ARTIFACTS:
            jar = f"{artifact}-{version}.jar"
            base = f"{MAVEN}/{group.replace('.', '/')}/{artifact}/{version}/{jar}"

            payload = fetch(base)
            # Verify against the published SHA-1 so a truncated download cannot
            # be published to the bucket and fail obscurely at job startup.
            expected = fetch(f"{base}.sha1").decode().split()[0].strip()
            actual = hashlib.sha1(payload).hexdigest()
            if expected != actual:
                sys.exit(f"SHA-1 mismatch for {jar}: expected {expected}, got {actual}")

            local = os.path.join(workdir, jar)
            with open(local, "wb") as handle:
                handle.write(payload)

            key = f"{PREFIX}/{jar}"
            s3.upload_file(local, BUCKET, key)
            size = s3.head_object(Bucket=BUCKET, Key=key)["ContentLength"]
            status = "ok" if size == len(payload) else "SIZE MISMATCH"
            print(f"s3a://{BUCKET}/{key}  {size:>9} bytes  {status}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
