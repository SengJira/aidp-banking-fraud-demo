#!/usr/bin/env bash
# Builds spark_jars_hdfs.tar.gz — the offline JAR bundle for the PySpark
# notebook (notebooks/banking_streaming_pyspark_hdfs.ipynb).
#
# Run this on a host WITH internet access (the Spark/Jupyter pod has no DNS),
# then copy the tarball to /home/jovyan/workspace on the Jupyter side.
#
# Target runtime: Spark 3.5.3 / Scala 2.12 / Java 17
set -euo pipefail

SPARK_VERSION="${SPARK_VERSION:-3.5.3}"
SPARK_MAJOR_MINOR="${SPARK_VERSION%.*}"
SCALA_VERSION="${SCALA_VERSION:-2.12}"
ICEBERG_VERSION="${ICEBERG_VERSION:-1.5.0}"
KAFKA_CLIENTS_VERSION="${KAFKA_CLIENTS_VERSION:-3.4.1}"   # per spark-sql-kafka-0-10 POM
COMMONS_POOL2_VERSION="${COMMONS_POOL2_VERSION:-2.11.1}"
HADOOP_VERSION="${HADOOP_VERSION:-3.3.4}"                 # match Spark's hadoop-client-*
AWS_SDK_V1_VERSION="${AWS_SDK_V1_VERSION:-1.12.262}"      # what hadoop-aws 3.3.4 needs

REPO="${MAVEN_REPO:-https://repo1.maven.org/maven2}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/dist}"
STAGE="$OUT_DIR/spark_jars"
TARBALL="$OUT_DIR/spark_jars_hdfs.tar.gz"

# groupId:artifactId:version — paths are derived below
ARTIFACTS=(
  # Iceberg: Spark runtime (shaded) + AWS clients for GlueCatalog / S3FileIO
  "org.apache.iceberg:iceberg-spark-runtime-${SPARK_MAJOR_MINOR}_${SCALA_VERSION}:${ICEBERG_VERSION}"
  "org.apache.iceberg:iceberg-aws-bundle:${ICEBERG_VERSION}"
  # Kafka source for Structured Streaming + its runtime deps
  "org.apache.spark:spark-sql-kafka-0-10_${SCALA_VERSION}:${SPARK_VERSION}"
  "org.apache.spark:spark-token-provider-kafka-0-10_${SCALA_VERSION}:${SPARK_VERSION}"
  "org.apache.kafka:kafka-clients:${KAFKA_CLIENTS_VERSION}"
  "org.apache.commons:commons-pool2:${COMMONS_POOL2_VERSION}"
  # Hadoop S3A + AWS SDK v1: lets the "s3://" scheme resolve for streaming
  # checkpoints (a different code path from Iceberg's S3FileIO)
  "org.apache.hadoop:hadoop-aws:${HADOOP_VERSION}"
  "com.amazonaws:aws-java-sdk-bundle:${AWS_SDK_V1_VERSION}"
)

rm -rf "$STAGE"
mkdir -p "$STAGE"

for coord in "${ARTIFACTS[@]}"; do
  IFS=':' read -r group artifact version <<<"$coord"
  jar="${artifact}-${version}.jar"
  url="${REPO}/${group//.//}/${artifact}/${version}/${jar}"

  echo "→ $jar"
  curl -fsSL "$url" -o "$STAGE/$jar"

  # Verify against the published SHA-1 so a truncated download can't silently
  # produce a broken bundle.
  expected=$(curl -fsSL "${url}.sha1" | tr -d '[:space:]' | cut -c1-40)
  actual=$(sha1sum "$STAGE/$jar" | cut -d' ' -f1)
  if [[ "$expected" != "$actual" ]]; then
    echo "   SHA-1 mismatch for $jar (expected $expected, got $actual)" >&2
    exit 1
  fi
done

tar -czf "$TARBALL" -C "$STAGE" .

echo
echo "Bundle: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
tar -tzf "$TARBALL" | grep '\.jar$' | sed 's|^\./|  |'
echo
echo "Copy it to the Jupyter side with:"
echo "  scp $TARBALL <jupyter-host>:/home/jovyan/workspace/"
