# bakalarka3


Exactly Python 3.7.x required until I upgrade to SSLyze 3.*


If you're running the program with with Redis you also have to run the following:
```
rq worker sslyze-tasks
rq worker --with-scheduler
```
