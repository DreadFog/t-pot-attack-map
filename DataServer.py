import datetime
import json
import time
import os
import pytz
import redis
from elasticsearch import Elasticsearch
from tzlocal import get_localzone

# Within T-Pot: es = Elasticsearch('http://elasticsearch:9200') and redis_ip = 'map_redis'
#es = Elasticsearch('http://127.0.0.1:64298')
#redis_ip = '127.0.0.1'
es = Elasticsearch('http://elasticsearch:9200')
redis_ip = 'map_redis'
redis_channel = 'attack-map-production'
version = 'Data Server 3.0.0'
local_tz = get_localzone()
output_text = os.getenv("TPOT_ATTACKMAP_TEXT", "ENABLED").upper()

# Track disconnection state for reconnection messages
was_disconnected_es = False
was_disconnected_redis = False

# Global Redis client for persistent connection
redis_client = None

event_count = 1

# Load configuration
with open('./config/port_config.json') as f:
    services = json.load(f)['services']

service_rgb = {name: info['color'] for name, info in services.items()}
PORT_MAP = {port: name for name, info in services.items() for port in info['ports']}

print(f"service rgb: " + str(service_rgb))
print(f"Port map: " + str(service_rgb))
def connect_redis(redis_ip):
    global redis_client
    try:
        # Check if existing connection is alive
        if redis_client:
            redis_client.ping()
            return redis_client
    except Exception:
        # Connection lost or invalid, reset
        pass
    
    # Create new connection
    redis_client = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return redis_client


def push_honeypot_stats(honeypot_stats):
    redis_instance = connect_redis(redis_ip)
    tmp = json.dumps(honeypot_stats)
    # print(tmp)
    redis_instance.publish(redis_channel, tmp)


def get_honeypot_stats(timedelta):
    ES_query_stats = {
        "bool": {
            "must": [],
            "filter": [
                {
                    "terms": {
                        "type.keyword": [
                            "Adbhoney", "Beelzebub", "Ciscoasa", "CitrixHoneypot", "ConPot",
                            "Cowrie", "Ddospot", "Dicompot", "Dionaea", "ElasticPot", 
                            "Endlessh", "Galah", "Glutton", "Go-pot", "H0neytr4p", "Hellpot", "Heralding", 
                            "Honeyaml", "Honeytrap", "Honeypots", "Log4pot", "Ipphoney", "Mailoney", 
                            "Medpot", "Miniprint", "Redishoneypot", "Sentrypeer", "Tanner", "Wordpot"
                        ]
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "strict_date_optional_time",
                            "gte": "now-" + timedelta,
                            "lte": "now"
                        }
                    }
                },
                {
                    "exists": {
                        "field": "geoip.ip"
                    }
                }
            ]
        }
    }
    return ES_query_stats


def update_honeypot_data():
    global was_disconnected_es, was_disconnected_redis
    processed_data = []
    last = {"1m", "1h", "24h"}
    mydelta = 10
    # Using timezone-aware UTC datetime (Python 3.14+ requirement)
    time_last_request = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)
    last_stats_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)
    while True:
        now = datetime.datetime.now(datetime.UTC)
        # Get the honeypot stats every 10s (last 1m, 1h, 24h)
        if (now - last_stats_time).total_seconds() >= 10:
            last_stats_time = now
            honeypot_stats = {}
            for i in last:
                try:
                    es_honeypot_stats = es.search(index="logstash-*", aggs={}, size=0, track_total_hits=True, query=get_honeypot_stats(i))
                    honeypot_stats.update({"last_"+i: es_honeypot_stats['hits']['total']['value']})
                except Exception as e:
                    # Connection errors are handled by outer exception handler
                    pass
            honeypot_stats.update({"type": "Stats"})
            push_honeypot_stats(honeypot_stats)

        # Get the last 100 new honeypot events every 0.5s
        # Convert timezone-aware datetime to naive for consistent string formatting with ES
        mylast_dt = time_last_request.replace(tzinfo=None)
        mynow_dt = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)).replace(tzinfo=None)
        
        mylast = str(mylast_dt).split(" ")
        mynow = str(mynow_dt).split(" ")
        
        ES_query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": (
                                "type:(Adbhoney OR Beelzebub OR Ciscoasa OR CitrixHoneypot OR ConPot OR Cowrie "
                                "OR Ddospot OR Dicompot OR Dionaea OR ElasticPot OR Endlessh OR Galah OR Glutton OR Go-pot OR H0neytr4p "
                                "OR Hellpot OR Heralding OR Honeyaml OR Honeypots OR Honeytrap OR Ipphoney OR Log4pot OR Mailoney "
                                "OR Medpot OR Miniprint OR Redishoneypot OR Sentrypeer OR Tanner OR Wordpot)"
                            )
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": mylast[0] + "T" + mylast[1],
                                "lte": mynow[0] + "T" + mynow[1]
                            }
                        }
                    }
                ]
            }
        }

        res = es.search(index="logstash-*", size=100, query=ES_query)
        hits = res['hits']
        if len(hits['hits']) != 0:
            time_last_request = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)
            for hit in hits['hits']:
                try:
                    process_datas = process_data(hit)
                    if process_datas != None:
                        processed_data.append(process_datas)
                except Exception:
                    pass
        if len(processed_data) != 0:
            push(processed_data)
            processed_data = []
        time.sleep(0.5)


def process_data(hit):
    alert = {}
    alert["honeypot"] = hit["_source"]["type"]
    alert["country"] = hit["_source"]["geoip"].get("country_name", "")
    alert["country_code"] = hit["_source"]["geoip"].get("country_code2", "")
    alert["continent_code"] = hit["_source"]["geoip"].get("continent_code", "")
    alert["dst_lat"] = hit["_source"]["geoip_ext"]["latitude"]
    alert["dst_long"] = hit["_source"]["geoip_ext"]["longitude"]
    alert["dst_ip"] = hit["_source"]["geoip_ext"]["ip"]
    alert["dst_iso_code"] = hit["_source"]["geoip_ext"].get("country_code2", "")
    alert["dst_country_name"] = hit["_source"]["geoip_ext"].get("country_name", "")
    alert["tpot_hostname"] = hit["_source"]["t-pot_hostname"]
    try:
        # Parse ISO timestamp (handles 'Z' in Python 3.11+)
        dt = datetime.datetime.fromisoformat(hit["_source"]["@timestamp"])
        alert["event_time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback to original slicing if parsing fails
        alert["event_time"] = str(hit["_source"]["@timestamp"][0:10]) + " " + str(hit["_source"]["@timestamp"][11:19])
    alert["iso_code"] = hit["_source"]["geoip"]["country_code2"]
    alert["latitude"] = hit["_source"]["geoip"]["latitude"]
    alert["longitude"] = hit["_source"]["geoip"]["longitude"]
    alert["dst_port"] = hit["_source"]["dest_port"]
    alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
    alert["src_ip"] = hit["_source"]["src_ip"]
    try:
        alert["src_port"] = hit["_source"]["src_port"]
    except Exception:
        alert["src_port"] = 0
    try:
        alert["ip_rep"] = hit["_source"]["ip_rep"]
    except Exception:
        alert["ip_rep"] = "reputation unknown"
    if not alert["src_ip"] == "":
        try:
            alert["color"] = service_rgb[alert["protocol"].upper()]
        except Exception:
            alert["color"] = service_rgb["OTHER"]
        return alert
    else:
        print("SRC IP EMPTY")
        return None


def port_to_type(port):
    try:
        return PORT_MAP.get(int(port), "OTHER")
    except Exception:
        return "OTHER"


def push(alerts):
    global event_count

    redis_instance = connect_redis(redis_ip)

    for alert in alerts:
        if output_text == "ENABLED":
            # Convert UTC to local time
            my_time = datetime.datetime.strptime(alert["event_time"], "%Y-%m-%d %H:%M:%S")
            my_time = my_time.replace(tzinfo=pytz.UTC)  # Assuming event_time is in UTC
            local_event_time = my_time.astimezone(local_tz)
            local_event_time = local_event_time.strftime("%Y-%m-%d %H:%M:%S")

            # Build the table data
            table_data = [
                [local_event_time, alert["country"], alert["src_ip"], alert["ip_rep"].title(),
                 alert["protocol"], alert["honeypot"], alert["tpot_hostname"]]
            ]

            # Define the minimum width for each column
            min_widths = [19, 20, 15, 18, 10, 14, 14]

            # Format and print each line with aligned columns
            for row in table_data:
                formatted_line = " | ".join(
                    "{:<{width}}".format(str(value), width=min_widths[i]) for i, value in enumerate(row))
                print(formatted_line)

        json_data = {
            "protocol": alert["protocol"],
            "color": alert["color"],
            "iso_code": alert["iso_code"],
            "honeypot": alert["honeypot"],
            "src_port": alert["src_port"],
            "event_time": alert["event_time"],
            "src_lat": alert["latitude"],
            "src_ip": alert["src_ip"],
            "ip_rep": alert["ip_rep"].title(),
            "type": "Traffic",
            "dst_long": alert["dst_long"],
            "continent_code": alert["continent_code"],
            "dst_lat": alert["dst_lat"],
            "event_count": event_count,
            "country": alert["country"],
            "src_long": alert["longitude"],
            "dst_port": alert["dst_port"],
            "dst_ip": alert["dst_ip"],
            "dst_iso_code": alert["dst_iso_code"],
            "dst_country_name": alert["dst_country_name"],
            "tpot_hostname": alert["tpot_hostname"]
        }
        event_count += 1
        tmp = json.dumps(json_data)
        redis_instance.publish(redis_channel, tmp)


def check_connections():
    """Check both Elasticsearch and Redis connections on startup."""
    print("[*] Checking connections...")
    
    es_ready = False
    redis_ready = False
    es_waiting_printed = False
    redis_waiting_printed = False
    
    while not (es_ready and redis_ready):
        # Check Elasticsearch
        if not es_ready:
            try:
                es.info()
                print("[*] Elasticsearch connection established")
                es_ready = True
            except Exception as e:
                if not es_waiting_printed:
                    print(f"[...] Waiting for Elasticsearch... (Error: {type(e).__name__})")
                    es_waiting_printed = True
        
        # Check Redis
        if not redis_ready:
            try:
                r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
                r.ping()
                print("[*] Redis connection established")
                redis_ready = True
            except Exception as e:
                if not redis_waiting_printed:
                    print(f"[...] Waiting for Redis... (Error: {type(e).__name__})")
                    redis_waiting_printed = True
        
        # If both not ready, wait before retrying
        if not (es_ready and redis_ready):
            time.sleep(5)
    
    return True

if __name__ == '__main__':
    print(version)
    
    # Check both connections on startup
    check_connections()
    print("[*] Starting data server...\n")
    
    try:
        while True:
            try:
                update_honeypot_data()
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                
                # Check for Redis errors
                if "6379" in error_msg or "Redis" in error_msg or "redis" in error_msg.lower():
                    if not was_disconnected_redis:
                        print(f"[ ] Connection lost to Redis ({error_type}), retrying...")
                        was_disconnected_redis = True
                # Check for Elasticsearch errors
                elif "Connection" in error_type or "urllib3" in error_msg or "elastic" in error_msg.lower():
                    if not was_disconnected_es:
                        print(f"[ ] Connection lost to Elasticsearch ({error_type}), retrying...")
                        was_disconnected_es = True
                else:
                    # DEBUG: Show unmatched errors to improve detection
                    print(f"[ ] Error: {error_type}: {error_msg}")
                    print(f"[DEBUG] Error details - Type: '{error_type}', Message: '{error_msg}'")
                
                # Proactively check connections to ensure we catch all failures
                if not was_disconnected_redis:
                    try:
                        r = connect_redis(redis_ip)
                        r.ping()
                    except:
                        print("[ ] Connection lost to Redis (Check), retrying...")
                        was_disconnected_redis = True
                
                if not was_disconnected_es:
                    try:
                        es.info()
                    except:
                        print("[ ] Connection lost to Elasticsearch (Check), retrying...")
                        was_disconnected_es = True

                time.sleep(5)
                if was_disconnected_es:
                    try:
                        es.info()
                        print("[*] Elasticsearch connection re-established")
                        was_disconnected_es = False
                    except:
                        pass
                
                # Test Redis
                if was_disconnected_redis:
                    try:
                        r = connect_redis(redis_ip)
                        r.ping()
                        print("[*] Redis connection re-established")
                        was_disconnected_redis = False
                    except:
                        pass

    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
