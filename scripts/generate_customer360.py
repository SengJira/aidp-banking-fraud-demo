#!/usr/bin/env python3
"""Generate a deterministic, entirely synthetic Customer 360 dataset.

This is deliberately separate from event generation: it produces the *stable
customer pool* that both MySQL and the Kafka event generator draw from, which is
what makes the federated join meaningful.

Outputs
-------
``<output-dir>/customer360.csv``
    Full master record, loaded into MySQL by ``scripts/load_customer360.py``.
``<output-dir>/customer_accounts.csv``
    Slim account pool consumed by ``generators/Streaming_gen.py``
    (``account_id``, ``customer_tier``, ``city``, ``country``).

Privacy
-------
No real personal data is used or derived. Names are assembled from small fixed
word lists, national IDs and phone numbers are masked patterns, and e-mail
addresses use the reserved ``.invalid`` TLD (RFC 6761) so they can never route
to a real mailbox.

Usage
-----
    python scripts/generate_customer360.py --customers 10000 --seed 42 --output-dir data
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from dataclasses import asdict, dataclass, fields
from datetime import date, timedelta
from pathlib import Path

# Account IDs are ACC-TH-10000001, ACC-TH-10000002, ... - contiguous and stable,
# so a given seed and customer count always produce the same pool.
ACCOUNT_PREFIX = "ACC-TH"
ACCOUNT_BASE = 10_000_000
CUSTOMER_ID_PREFIX = "CUST-DEMO"

DEFAULT_CUSTOMERS = 10_000
DEFAULT_SEED = 42
DEFAULT_OUTPUT_DIR = "data"

CUSTOMER_CSV = "customer360.csv"
ACCOUNTS_CSV = "customer_accounts.csv"

# Fixed word lists. 10k customers drawn from ~40x40 combinations produce many
# repeated names, which is intentional: the dataset must read as generated.
GIVEN_NAMES = (
    "Somchai",
    "Somsak",
    "Somporn",
    "Anan",
    "Chaiwat",
    "Kittisak",
    "Narong",
    "Prasert",
    "Sarawut",
    "Thanakorn",
    "Wichai",
    "Adisak",
    "Boonmee",
    "Decha",
    "Ekachai",
    "Krit",
    "Nattapong",
    "Pichai",
    "Sakda",
    "Weerachai",
    "Suda",
    "Malee",
    "Nong",
    "Pranee",
    "Siriporn",
    "Wanida",
    "Achara",
    "Duangjai",
    "Kanya",
    "Ladda",
    "Napaporn",
    "Orathai",
    "Pimchanok",
    "Ratana",
    "Sunisa",
    "Thidarat",
    "Ubon",
    "Waraporn",
    "Yupin",
    "Chanida",
)
FAMILY_NAMES = (
    "Jaidee",
    "Sooksai",
    "Rakthai",
    "Boonsong",
    "Chaiyaporn",
    "Wongsawat",
    "Srisuk",
    "Thongchai",
    "Kittikun",
    "Phromma",
    "Sae-Lim",
    "Ratanakul",
    "Intharat",
    "Kaewkla",
    "Nakarin",
    "Pongpanit",
    "Rungruang",
    "Sittichai",
    "Thanapat",
    "Udomsak",
    "Viriya",
    "Wattana",
    "Yodsawat",
    "Chanthara",
    "Damrong",
    "Ekwannang",
    "Grittiya",
    "Hemmawat",
    "Issaraphon",
    "Jitkasem",
    "Khemthong",
    "Lertsakul",
    "Maneerat",
    "Nithiwat",
    "Oonsuwan",
    "Pattarapon",
    "Rojanasak",
    "Sombuntham",
    "Traiphop",
    "Wisitsak",
)

# (city, province, postal prefix, weight) - weights mirror the existing event
# generator so payment traffic and customer master data agree geographically.
CITIES = (
    ("Bangkok", "Bangkok", "10", 0.55),
    ("Chiang Mai", "Chiang Mai", "50", 0.15),
    ("Pattaya", "Chonburi", "20", 0.12),
    ("Phuket", "Phuket", "83", 0.10),
    ("Khon Kaen", "Khon Kaen", "40", 0.08),
)

TIERS = (("STANDARD", 0.35), ("SILVER", 0.40), ("GOLD", 0.20), ("PLATINUM", 0.05))
RISK_RATINGS = (("LOW", 0.70), ("MEDIUM", 0.25), ("HIGH", 0.05))
KYC_STATUSES = (("VERIFIED", 0.85), ("PENDING", 0.10), ("EXPIRED", 0.05))
SANCTIONS_STATUSES = (
    ("CLEAR", 0.965),
    ("PENDING_REVIEW", 0.030),
    ("MATCH_REVIEW", 0.005),
)
GENDERS = (("FEMALE", 0.49), ("MALE", 0.49), ("OTHER", 0.02))
PREFERRED_CHANNELS = (
    ("MOBILE_APP", 0.45),
    ("ONLINE_BANKING", 0.25),
    ("POS", 0.15),
    ("BRANCH", 0.10),
    ("ATM", 0.05),
)
OCCUPATIONS = (
    "Software Engineer",
    "Teacher",
    "Nurse",
    "Civil Servant",
    "Shop Owner",
    "Accountant",
    "Chef",
    "Hotel Manager",
    "Tour Guide",
    "Farmer",
    "Sales Executive",
    "Graphic Designer",
    "Logistics Coordinator",
    "Bank Officer",
    "Doctor",
    "Lawyer",
    "Electrician",
    "Student",
    "Retired",
    "Freelance Consultant",
)
PEP_RATE = 0.02
MARKETING_CONSENT_RATE = 0.60

# Income bands per tier: (minimum THB, maximum THB).
TIER_INCOME = {
    "STANDARD": (180_000, 600_000),
    "SILVER": (500_000, 1_200_000),
    "GOLD": (1_000_000, 3_500_000),
    "PLATINUM": (3_000_000, 25_000_000),
}

# (low age, high age, label, weight). The age group is drawn first and the exact
# age uniformly within it; drawing the age uniformly across 18-82 instead would
# over-fill the wide "65+" bucket (~28% rather than a realistic ~9%).
AGE_GROUPS = (
    (18, 24, "18-24", 0.12),
    (25, 34, "25-34", 0.24),
    (35, 44, "35-44", 0.23),
    (45, 54, "45-54", 0.19),
    (55, 64, "55-64", 0.13),
    (65, 82, "65+", 0.09),
)


@dataclass(frozen=True)
class Customer:
    """One synthetic Customer 360 record (column order matches the MySQL table)."""

    customer_id: str
    account_id: str
    full_name: str
    national_id_masked: str
    date_of_birth: str
    age_group: str
    gender: str
    email: str
    mobile_number_masked: str
    city: str
    province: str
    country: str
    postal_code: str
    customer_tier: str
    occupation: str
    annual_income: str
    risk_rating: str
    kyc_status: str
    pep_flag: int
    sanctions_screening_status: str
    account_open_date: str
    preferred_channel: str
    marketing_consent: int
    created_at: str
    updated_at: str


CUSTOMER_COLUMNS = tuple(f.name for f in fields(Customer))
ACCOUNT_POOL_COLUMNS = ("account_id", "customer_tier", "city", "country")


def _weighted(rng: random.Random, choices: tuple) -> str:
    """Pick from a ((value, weight), ...) tuple."""
    values = [value for value, _ in choices]
    weights = [weight for _, weight in choices]
    return rng.choices(values, weights=weights, k=1)[0]


def account_id_for(index: int) -> str:
    """Stable account ID for the 1-based customer index."""
    return f"{ACCOUNT_PREFIX}-{ACCOUNT_BASE + index}"


def _draw_age(rng: random.Random) -> tuple[int, str]:
    """Draw an age group by weight, then an exact age uniformly within it."""
    low, high, label, _ = rng.choices(
        AGE_GROUPS, weights=[weight for *_, weight in AGE_GROUPS], k=1
    )[0]
    return rng.randint(low, high), label


def make_customer(index: int, rng: random.Random, today: date) -> Customer:
    """Build one deterministic synthetic customer for the 1-based index."""
    given = rng.choice(GIVEN_NAMES)
    family = rng.choice(FAMILY_NAMES)

    city, province, postal_prefix, _ = rng.choices(
        CITIES, weights=[weight for *_, weight in CITIES], k=1
    )[0]

    tier = _weighted(rng, TIERS)
    income_low, income_high = TIER_INCOME[tier]

    age, age_group = _draw_age(rng)
    birth = today - timedelta(days=age * 365 + rng.randint(0, 364))

    # Opened between 1 and 12 years ago, never before the customer turned 18.
    max_tenure_days = min(12 * 365, max(1, (today - birth).days - 18 * 365))
    opened = today - timedelta(days=rng.randint(1, max_tenure_days))

    # A PEP or an unresolved sanctions hit realistically skews the risk rating.
    pep_flag = 1 if rng.random() < PEP_RATE else 0
    risk = _weighted(rng, RISK_RATINGS)
    if pep_flag and risk == "LOW" and rng.random() < 0.7:
        risk = "MEDIUM"

    # Derived from the as-of date rather than wall-clock now(), so the same seed
    # and as-of date always produce a byte-identical file.
    created_at = f"{opened.isoformat()} 00:00:00"
    updated_at = f"{today.isoformat()} 00:00:00"

    return Customer(
        customer_id=f"{CUSTOMER_ID_PREFIX}-{index:07d}",
        account_id=account_id_for(index),
        full_name=f"{given} {family}",
        # Masked to the shape of a Thai national ID; only a check digit is shown.
        national_id_masked=f"X-XXXX-XXXXX-XX-{rng.randint(0, 9)}",
        date_of_birth=birth.isoformat(),
        age_group=age_group,
        gender=_weighted(rng, GENDERS),
        # .invalid is reserved by RFC 6761 and can never resolve.
        email=f"{given.lower()}.{family.lower().replace('-', '')}{index}@example.invalid",
        mobile_number_masked=f"+66-XX-XXX-{rng.randint(0, 9999):04d}",
        city=city,
        province=province,
        country="TH",
        postal_code=f"{postal_prefix}{rng.randint(0, 999):03d}",
        customer_tier=tier,
        occupation=rng.choice(OCCUPATIONS),
        annual_income=f"{rng.uniform(income_low, income_high):.2f}",
        risk_rating=risk,
        kyc_status=_weighted(rng, KYC_STATUSES),
        pep_flag=pep_flag,
        sanctions_screening_status=_weighted(rng, SANCTIONS_STATUSES),
        account_open_date=opened.isoformat(),
        preferred_channel=_weighted(rng, PREFERRED_CHANNELS),
        marketing_consent=1 if rng.random() < MARKETING_CONSENT_RATE else 0,
        created_at=created_at,
        updated_at=updated_at,
    )


def generate_customers(
    count: int, seed: int, today: date | None = None
) -> list[Customer]:
    """Generate ``count`` customers deterministically from ``seed``.

    Uses a private ``random.Random`` instance so the global RNG - and therefore
    anything else in the process - is left untouched.
    """
    if count < 1:
        raise ValueError(f"--customers must be at least 1, got {count}")
    rng = random.Random(seed)
    today = today or date.today()
    return [make_customer(i, rng, today) for i in range(1, count + 1)]


def write_customer_csv(customers: list[Customer], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CUSTOMER_COLUMNS)
        writer.writeheader()
        for customer in customers:
            writer.writerow(asdict(customer))


def write_account_pool_csv(customers: list[Customer], path: Path) -> None:
    """Write the slim pool the Kafka generator reads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ACCOUNT_POOL_COLUMNS)
        writer.writeheader()
        for customer in customers:
            writer.writerow(
                {
                    "account_id": customer.account_id,
                    "customer_tier": customer.customer_tier,
                    "city": customer.city,
                    "country": customer.country,
                }
            )


def summarize(customers: list[Customer]) -> dict[str, dict[str, int]]:
    """Count the distributions worth eyeballing after a run."""
    summary: dict[str, dict[str, int]] = {}
    for attribute in (
        "customer_tier",
        "risk_rating",
        "kyc_status",
        "city",
        "sanctions_screening_status",
        "age_group",
    ):
        counts: dict[str, int] = {}
        for customer in customers:
            value = getattr(customer, attribute)
            counts[value] = counts.get(value, 0) + 1
        summary[attribute] = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
    summary["pep_flag"] = {
        "PEP": sum(c.pep_flag for c in customers),
        "NON_PEP": sum(1 - c.pep_flag for c in customers),
    }
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate synthetic Customer 360 data for the AIDP federated demo.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--customers",
        type=int,
        default=DEFAULT_CUSTOMERS,
        help="Number of synthetic customers to generate",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed; the same seed always yields the same dataset",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for customer360.csv and customer_accounts.csv",
    )
    parser.add_argument(
        "--as-of-date",
        type=date.fromisoformat,
        default=None,
        help="Reference date (YYYY-MM-DD) for ages and open dates. "
        "Defaults to today; pin it for byte-identical reruns.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    customers = generate_customers(args.customers, args.seed, args.as_of_date)
    output_dir = Path(args.output_dir)
    customer_path = output_dir / CUSTOMER_CSV
    accounts_path = output_dir / ACCOUNTS_CSV

    write_customer_csv(customers, customer_path)
    write_account_pool_csv(customers, accounts_path)

    print(f"Generated {len(customers):,} synthetic customers (seed={args.seed})")
    print(
        f"  account ID range : {customers[0].account_id} .. {customers[-1].account_id}"
    )
    print(f"  full dataset     : {customer_path}")
    print(f"  Kafka pool       : {accounts_path}")
    print("\nDistributions:")
    for attribute, counts in summarize(customers).items():
        rendered = ", ".join(
            f"{value}={count:,} ({100.0 * count / len(customers):.1f}%)"
            for value, count in counts.items()
        )
        print(f"  {attribute:28s} {rendered}")
    print(
        "\nAll values are synthetic: names come from fixed word lists, national IDs "
        "and phone numbers are masked patterns, and e-mail uses the reserved "
        ".invalid TLD."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
