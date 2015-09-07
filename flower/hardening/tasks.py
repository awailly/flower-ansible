from celery import Celery
from pprint import pprint
from collections import OrderedDict

import subprocess
import uuid
# import redis
import datetime
import requests
import json
import re
from lxml import etree

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
                found = 1

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


def patch_history(callback, status, results=None, details=None):
    """
    Do not catch exception, it is better to kill the task and show the
    appropriate error in the celery console
    """
    headers = {'content-type': 'application/json'}

    data = {"status": status}
    if results:
        data["results"] = results
    if details:
        finald = []
        for k in details:
            finald.append({"key": k, "value": details[k]})
        data["details"] = finald

    print("Sending %s" % repr(data))
    r = requests.patch(callback, data=json.dumps(data), headers=headers)

    if r.status_code == 200:
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
    command = 'stdbuf -oL -eL ansible-playbook -e "pipelining=True" -b -u %s --private-key=%s -i %s, -t %s %s' % (user, key, ip, tag, playbook)
    print(repr(command.split(" ")))

    print(repr(callback))
    patch_history(callback, "St")
    p = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE, bufsize=1)
    #output = p.communicate()[0]
    #print(output)

    result = {}
    result['returncode'] = p.returncode

    got_task = False
    final_next = False
    task_name = ""

    with p.stdout:
        for line in iter(p.stdout.readline, b''):
            print(repr(line))

            output = line

            if got_task == False and "TASK: " not in output:
                print("Waiting for TASK")
                continue
            elif final_next == True:
                print("Final")
                patch_history(callback, "St", details=details)
                score = output.split(":")[1].split("\n")[0]
                items = score.split(" ")
                results = {}
                for item in items:
                    if len(item):
                        eq = item.split("=")
                        results[eq[0]] = eq[1]

                patch_history(callback, "Su", results)
                print("!!!!! Fini !!!!!!")
                break
            elif output == "\n":
                continue
            elif got_task:
                print("In TASK")
                if "TASK: " not in output:
                    print("adding")
                    audit_value = output.split(":")[0]
                    details[task_name] += "%s\n" % (audit_value,)
                else:
                    print("patching")
                    patch_history(callback, "St", details=details)
            try:
                if "SSH Error: Permission denied (publickey)" in output:
                    raise Exception("SSH Error: Permission denied (publickey)")

                if "PLAY RECAP" in output:
                    print("Play recap")
                    final_next = True

                if "TASK: " in output:
                    print("in task = True")
                    got_task = True
                    details = {}

                    audit_key = re.search('(\d)(.+)(\))', output).group(0)
                    task_name = audit_key
                    details[task_name] = ""

            except:
                patch_history(callback, "Fa")
                result['error'] = output
                raise

    # print(r.hgetall("audit_%s" % vmid))

    return result

@app.task
def scanning_ex(vmid, callback, ip, port):
    result = {}
    result['id'] = str(uuid.uuid4())

    command = 'nmap -T4 -oX /tmp/scan.xml -vvv --reason -p %s %s' % (port, ip)
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
        results = { "key": "lol" }
        r = etree.parse('/tmp/scan.xml').getroot()
        r = r.findall('.//port')
        print(repr(r))

        details = {}

        for port in r:
            port_number = port.values()[1]
            status = list(port).values()[0]
            print(repr(values))
            details[port_number] = status

        _details = details

        patch_history(callback, "Su", results=results, details=_details)
    except:
        patch_history(callback, "Fa")
        result['error'] = output
        raise

    return result
