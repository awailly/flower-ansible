# flower-ansible
Automated scheduler and monitoring

# Ansible 

```bash
ansible-playbook -e "pipelining=True" -b -u ubuntu --private-key=~/.ssh/id_rsa -i "172.30.3.12," fullsetup.yml
```

# API

[Full flower API documentation](http://flower.readthedocs.org/en/latest/api.html) and [examples](http://nbviewer.ipython.org/github/mher/flower/blob/master/docs/api.ipynb)

## Adding a task

```bash
  curl -u user:password -X POST -d '{"args":[1,2]}' http://172.30.3.12:5555/api/task/async-apply/tasks.add
```

## Listing tasks

```bash
  curl -u user:password http://172.30.3.12:5555/api/tasks
```

