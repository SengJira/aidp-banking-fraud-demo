#!/usr/bin/env python3
"""banking_producer.py — Standalone banking event producer for Kafka
   pip install kafka-python faker
"""
import json, time, random, uuid
from datetime import datetime, timezone
from faker import Faker
from kafka import KafkaProducer
import threading

fake = Faker()
BOOTSTRAP = '48.64.33.52:9092'

CITIES = ['Bangkok', 'Chiang Mai', 'Pattaya', 'Phuket', 'Khon Kaen']
CITY_COORDS = {
    'Bangkok':    (13.7563, 100.5018),
    'Chiang Mai': (18.7883, 98.9853),
    'Pattaya':    (12.9236, 100.8825),
    'Phuket':     (7.8804,  98.3923),
    'Khon Kaen':  (16.4419, 102.8360),
}
CHANNELS   = ['POS', 'MOBILE_APP', 'ONLINE_BANKING', 'ATM', 'BRANCH']
CH_WEIGHTS = [0.40, 0.30, 0.18, 0.08, 0.04]
MCCS       = ['RETAIL', 'FOOD_BEVERAGE', 'TRAVEL', 'HEALTHCARE',
              'UTILITIES', 'ENTERTAINMENT', 'EDUCATION', 'FUEL']
TIERS      = ['PLATINUM', 'GOLD', 'SILVER', 'STANDARD']
FRAUD_TYPES = ['CARD_NOT_PRESENT', 'ACCOUNT_TAKEOVER',
               'IDENTITY_THEFT', 'SYNTHETIC_IDENTITY']

def make_producer():
    return KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None,
        compression_type='snappy',
        batch_size=16384,
        linger_ms=10,
        acks='all',
        retries=3,
    )

def rand_account():
    return f'ACC-TH-{random.randint(10000000,99999999)}'

def gen_payment():
    city = random.choices(CITIES, weights=[0.55,0.15,0.12,0.10,0.08])[0]
    lat, lon = CITY_COORDS[city]
    etype = random.choices(
        ['CARD_PAYMENT','WIRE_TRANSFER','ATM_WITHDRAWAL','ACH_TRANSFER'],
        [0.55,0.20,0.15,0.10])[0]
    acct = rand_account()
    amount = round(random.choices(
        [random.uniform(50,5000), random.uniform(5001,500000)],
        [0.85,0.15])[0], 2)
    event = {
        'event_id':         f'txn_{uuid.uuid4().hex[:8]}',
        'event_type':       etype,
        'timestamp':        datetime.now(timezone.utc).isoformat(),
        'transaction_id':   f'TXN-{datetime.now().strftime("%Y%m%d")}-{random.randint(1000000,9999999)}',
        'account_id':       acct,
        'amount':           amount,
        'currency':         random.choices(['THB','USD','EUR','SGD'],[.80,.10,.06,.04])[0],
        'channel':          random.choices(CHANNELS, CH_WEIGHTS)[0],
        'merchant_category': random.choice(MCCS),
        'status':           random.choices(
                              ['APPROVED','DECLINED','PENDING','REVERSED'],
                              [.88,.08,.03,.01])[0],
        'city':             city,
        'country':          random.choices(['TH','SG','MY','JP','US'],[.78,.08,.06,.04,.04])[0],
        'latitude':         round(lat + random.uniform(-0.2, 0.2), 6),
        'longitude':        round(lon + random.uniform(-0.2, 0.2), 6),
        'is_international': random.random() < 0.12,
        'customer_tier':    random.choices(TIERS,[.05,.20,.40,.35])[0],
        'risk_score':       round(random.uniform(0, 0.35), 3),
    }
    return event, acct

def gen_fraud_signal():
    acct = rand_account()
    return {
        'event_id':         f'fraud_{uuid.uuid4().hex[:8]}',
        'event_type':       'FRAUD_SIGNAL',
        'timestamp':        datetime.now(timezone.utc).isoformat(),
        'account_id':       acct,
        'fraud_type':       random.choice(FRAUD_TYPES),
        'ml_score':         round(random.uniform(0.70, 1.0), 3),
        'rule_triggers':    random.sample(
                              ['VELOCITY_BREACH','GEO_ANOMALY','NEW_DEVICE',
                               'UNUSUAL_AMOUNT','NIGHT_TXN','WATCHLIST_HIT'],
                              k=random.randint(1,3)),
        'action':           random.choice(['BLOCK_AND_ALERT','FLAG_REVIEW','STEP_UP_AUTH']),
        'case_id':          f'CASE-{datetime.now().year}-{random.randint(100000,999999)}',
    }, acct

def gen_customer_event():
    acct = rand_account()
    etype = random.choices(
        ['CUSTOMER_LOGIN','AML_ALERT','PROFILE_CHANGE','ACCOUNT_OPEN'],
        [0.60,0.20,0.15,0.05])[0]
    event = {
        'event_id':   f'cust_{uuid.uuid4().hex[:8]}',
        'event_type': etype,
        'timestamp':  datetime.now(timezone.utc).isoformat(),
        'account_id': acct,
    }
    if etype == 'AML_ALERT':
        event.update({
            'alert_type':     random.choice(['STRUCTURING','LAYERING','ROUND_TRIPPING']),
            'risk_band':      random.choice(['HIGH','MEDIUM']),
            'sar_required':   random.random() < 0.4,
            'total_amount_7d': round(random.uniform(100000, 1000000), 2),
        })
    elif etype == 'CUSTOMER_LOGIN':
        event.update({
            'channel':      random.choice(['MOBILE_APP','WEB']),
            'auth_method':  random.choice(['BIOMETRIC','OTP','PASSWORD']),
            'login_success': random.random() < 0.95,
            'new_device':   random.random() < 0.05,
        })
    return event, acct

def produce_loop(producer, topic, gen_fn, eps, stop_event):
    interval = 1.0 / eps
    while not stop_event.is_set():
        t0 = time.time()
        event, key = gen_fn()
        producer.send(topic, value=event, key=key)
        elapsed = time.time() - t0
        if elapsed < interval:
            time.sleep(interval - elapsed)

if __name__ == '__main__':
    p = make_producer()
    stop = threading.Event()
    threads = [
        threading.Thread(target=produce_loop, args=(p, 'payments.raw',   gen_payment,        50, stop)),
        threading.Thread(target=produce_loop, args=(p, 'fraud.signals',   gen_fraud_signal,   10, stop)),
        threading.Thread(target=produce_loop, args=(p, 'customer.events', gen_customer_event,  5, stop)),
    ]
    for t in threads: t.daemon = True; t.start()
    print('[BankingProducer] Running — Ctrl+C to stop')
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        stop.set(); p.flush(); print('[BankingProducer] Stopped')