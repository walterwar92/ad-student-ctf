"""Resolve which teams to attack. Three modes (set in config['targets']['mode']):

  template        : ids -> name 'teamN'; host/port computed by config.resolve_address
  list            : explicit {name: host}; port = the service's configured port
  from_attackdata : teams are the keys of the fetched attack-data (handled in runner)

Your own team (config['my_team_id']) is always excluded.
"""


def _idof(s):
    d = "".join(c for c in str(s) if c.isdigit())
    return int(d) if d else None


def resolve(cfg):
    t = cfg["targets"]
    mine = cfg.get("my_team_id")
    mode = t.get("mode", "template")
    out = []
    if mode == "list":
        for name, host in t.get("list", {}).items():
            if _idof(name) == mine:
                continue
            out.append({"name": name, "host": host, "id": _idof(name)})
    elif mode == "template":
        for i in t.get("ids", []):
            if i == mine:
                continue
            name = t.get("name_template", "team%d") % i
            out.append({"name": name, "host": None, "id": i})
    # from_attackdata is resolved by the runner once the data is fetched
    return out
