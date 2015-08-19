from celery import Celery
from subprocess import call

app = Celery('tasks')
app.config_from_object('celeryconfig')

@app.task
def add(x, y):
    return x + y

@app.task
def hardening_ex(user, ip, tag):
    command = 'ansible-playbook -e "pipelining=True" -b -u %s --private-key=~/.ssh/id_rsa -i "%s," -t %s playbook.yml' % (user, ip, tag)
    retcode = call(command.split(" "))
    return retcode
