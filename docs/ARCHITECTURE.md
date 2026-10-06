# TraceFact Architecture

TraceFact has one local core. Platform specific collectors feed the same event model, so the analysis code does not need to know which operating system produced an event.

```text
                         TRACEFACT
                             |
                 +-----------+-----------+
                 |                       |
              Rust Core            TypeScript UI
                 |
          +------+-------+
          |      |       |
       Process  Network  Filesystem
       collector collector collector
          |      |       |
          +------+-------+
                 |
             Event Model
                 |
             Runtime Model
                 |
          +------+-------+
          |              |
     Behavior Diff    Policy Engine
          |              |
          +------+-------+
                 |
              SQLite
                 |
          Passport / Reports
                 |
          Optional AI layer
```

The Rust core owns collection, normalization, analysis, storage, and the local API.

The web interface talks to the local core. For the initial desktop experience, nothing needs to be uploaded to a remote service.

The LLM is not the source of truth. Facts come from observed events. Later, an optional AI layer can explain those facts in plain language.
