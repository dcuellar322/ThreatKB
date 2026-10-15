from pathlib import Path
from uuid import uuid4
import json
import click
import yaml
from .engine import Repository, load

@click.group()
@click.option('--root',type=click.Path(path_type=Path),default=Path('detections'))
@click.pass_context
def cli(ctx,root): ctx.obj=root

@cli.command('ids')
@click.pass_obj
def ids(root):
    for path in (root/'rules').glob('*.yaml'):
        rule=load(path)
        if rule.get('id') in (None,'AUTO'):
            rule['id']=str(uuid4()); path.write_text(yaml.safe_dump(rule,sort_keys=False))

@cli.command('check')
@click.option('--group',default='default')
@click.option('--corpus',type=click.Path(path_type=Path))
@click.option('--goodware',type=click.Path(path_type=Path))
@click.pass_obj
def check(root,group,corpus,goodware): click.echo(json.dumps(Repository(root,corpus).check(group,goodware)))

@cli.command('build')
@click.option('--group',default='default')
@click.option('--kind',type=click.Choice(['sigpack','feedpack','codepack']),default='sigpack')
@click.option('--corpus',type=click.Path(path_type=Path))
@click.option('--goodware',type=click.Path(path_type=Path))
@click.option('--output',type=click.Path(path_type=Path),default=Path('instance/builds'))
@click.pass_obj
def build(root,group,kind,corpus,goodware,output): click.echo(json.dumps(Repository(root,corpus).build(output,group,kind,goodware)))

if __name__=='__main__': cli()
