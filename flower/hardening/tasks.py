from celery import Celery
import subprocess
import uuid
import redis
import datetime
import requests
import json
from pprint import pprint

app = Celery('tasks')
app.config_from_object('celeryconfig')

@app.task
def add(x, y):
    return x + y

def trust_host(ip):
    found = 0
    with open("/home/ubuntu/.ssh/known_hosts", "r") as myfile:
        lines = myfile.readlines()
        for line in lines:
            if ip in line:
                found=1

    if found:
        print("Already trusted IP")
        return 0

    p = subprocess.Popen(["ssh-keyscan", ip], stdout=subprocess.PIPE)
    output = p.communicate()[0]
    key = output

    if "ssh" not in key:
        return 1

    with open("/home/ubuntu/.ssh/known_hosts", "a") as myfile:
        print("Writing key to known_hosts")
        myfile.write(key)

    return p.returncode

def get_credentials(vmid):
    priv_key = "~/.ssh/id_rsa"
    return ("ubuntu", priv_key)

def patch_history(callback, status):
    """
    Do not catch exception, it is better to kill the task and show the
    appropriate error in the celery console
    """
    headers = {'content-type': 'application/json'}

    data = { "status" : status }
    r = requests.patch(callback, data=json.dumps(data), headers=headers)

    if r.status_code == 200:
        pprint(r.json())
        return r.json()["id"]
    else:
        return r.text

@app.task
def hardening_ex(vmid, callback, ip, tag):
    result = {}
    result['id'] = str(uuid.uuid4())
    status = trust_host(ip)

    if status != 0:
        result['returncode'] = 1
        result['error'] = 'Unable to trust host %s' % repr(ip)
        return result

    user, key = get_credentials(vmid)
    playbook = "/home/ubuntu/ansible/roles-ubuntu/playbook.yml"

    print("%s %s %s" % (repr(user), repr(ip), repr(tag)))
    command = 'ansible-playbook -e "pipelining=True" -b -u %s --private-key=%s -i %s, -t %s %s' % (user, key, ip, tag, playbook)
    print(repr(command.split(" ")))

    print(repr(callback))
    patch_history(callback, "St")
    p = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)
    output = p.communicate()[0]
    print(output)

    result = {}
    result['returncode'] = p.returncode

    try:
        date = datetime.datetime.now().isoformat()
        formatted_audit = {}

        patch_history(callback, "Su")

        r = redis.Redis('localhost')
        r.hset("audit:%s" % vmid, "date", date)

        score = output.split("PLAY RECAP")[1].split(":")[1].split("\n")[0]
        r.hset("audit:%s:evolution" % vmid, date, score)

        # Removing the first with useless information
        tasks = output.split("TASK:")[1:]
        for task in tasks:
            audit_key = task.split("]")[0].split("[")[1]
            audit_value = task.split("\n")[1:]
            r.hset("audit_%s" % vmid, audit_key, audit_value)
    except:
        patch_history(callback, "Fa")
        result['error'] = output

    #print(r.hgetall("audit_%s" % vmid))

    return result
