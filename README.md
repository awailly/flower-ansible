# flower-ansible
Automated scheduler and monitoring

# API

[Full flower API documentation](http://flower.readthedocs.org/en/latest/api.html) and [examples](http://nbviewer.ipython.org/github/mher/flower/blob/master/docs/api.ipynb)

## Adding a task

  curl -X POST -d '{"args":[1,2]}' http://172.30.3.12:5555/api/task/async-apply/tasks.add

## Listing tasks

  curl http://172.30.3.12:5555/api/tasks

