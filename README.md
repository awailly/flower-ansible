# flower-ansible
Automated scheduler and monitoring

# API

## Adding a task

  curl -X POST -d '{"args":[1,2]}' http://172.30.3.12:5555/api/task/async-apply/tasks.add

## Listing tasks

  curl http://172.30.3.12:5555/api/tasks
