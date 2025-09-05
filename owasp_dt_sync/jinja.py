import jinja2

__template_env: jinja2.Environment = None

def setup_jina_env():
    from owasp_dt_sync import globals
    global __template_env
    if not __template_env:
        search_paths = []
        search_paths.append(globals.template_path.parent)
        template_loader = jinja2.FileSystemLoader(searchpath=search_paths)
        __template_env = jinja2.Environment(
            loader=template_loader,
            trim_blocks=True,
            lstrip_blocks=True
        )
        # template_env.filters['regex_replace'] = models.regex_replace
        # template_env.tests['is_not_defined'] = models.is_not_defined
        # template_env.tests['is_defined'] = models.is_defined
        #__template_env.globals["env"] = lambda name, default=None: os.getenv(name, default)
    return __template_env

def get_template():
    env = setup_jina_env()
    from owasp_dt_sync import globals
    return env.get_template(globals.template_path.name)
