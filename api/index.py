from run import app as app

# Ensure a root route exists; if the app already defines '/', do nothing.
try:
    has_root = any(rule.rule == '/' for rule in app.url_map.iter_rules())
except Exception:
    has_root = False

if not has_root:
    @app.route('/')
    def _index():
        return 'Inventory Management is running.'
