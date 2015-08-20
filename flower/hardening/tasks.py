from celery import Celery
import subprocess
import uuid

app = Celery('tasks')
app.config_from_object('celeryconfig')

@app.task
def add(x, y):
    return x + y

def trust_host(ip):
    p = subprocess.Popen(["ssh-keyscan", ip], stdout=subprocess.PIPE)
    output = p.communicate()[0]
    key = output.split("\n")[-1]
    print("Found key: %s" % key)
    return p.returncode

def get_credentials(vmid):
    priv_key = "~/.ssh/id_rsa"
    return ("ubuntu", priv_key)

@app.task
def hardening_ex(vmid, ip, tag):
    trust_host(ip)
    user,key = get_credentials(vmid)
    playbook = "/home/ubuntu/ansible/roles-ubuntu/playbook.yml"

    print("%s %s %s" % (repr(user), repr(ip), repr(tag)))
    command = 'ansible-playbook -e "pipelining=True" -b -u %s --private-key=%s -i %s -t %s %s' % (user, key, ip, tag, playbook)
    print(repr(command.split(" ")))

    p = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)
    output = p.communicate()[0]
    print(output)

    result = {}
    result['returncode'] = returncode
    result['id'] = uuid.uuid4()

    return p.returncode
