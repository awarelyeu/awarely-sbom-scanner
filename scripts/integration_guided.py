"""Exercise the built guided CLI, consent boundaries and managed Syft offline."""
import json,os,pathlib,re,shutil,subprocess,sys,tempfile,zipfile
binary=str(pathlib.Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory(prefix='awarely-guided-test-') as directory:
 root=pathlib.Path(directory);app=root/'app';app.mkdir()
 (app/'package-lock.json').write_text('{"lockfileVersion":3,"packages":{"node_modules/demo":{"version":"1.0.0"}}}')
 (app/'requirements.txt').write_text('requests==2.31.0\n')
 with zipfile.ZipFile(app/'demo.jar','w') as jar:
  jar.writestr('META-INF/maven/org.example/demo/pom.properties','groupId=org.example\nartifactId=demo\nversion=1.0.0\n')
  jar.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\nImplementation-Version: 1.0.0\n')
 # A project configuration and parent environment must never enable enrichment.
 (app/'.syft.yaml').write_text('check-for-app-update: true\njava:\n  use-network: true\n')
 environment={**os.environ,'HOME':str(root),'SYFT_JAVA_USE_NETWORK':'true','GH_TOKEN':'synthetic-must-not-be-in-child-env'}
 def run(name,answers,expected=0,isolated=False):
  cmd=[binary,'guided']
  if isolated:
   trace=root/(name+'.trace')
   cmd=['sudo','unshare','--net','--setuid',str(os.getuid()),'--setgid',str(os.getgid()),'--',
     'env','-i','HOME='+str(root),'PATH=/usr/bin:/bin','SYFT_JAVA_USE_NETWORK=true',
     'strace','-f','-e','trace=network,execve','-o',str(trace),*cmd]
  result=subprocess.run(cmd,input='\n'.join(answers)+'\n',text=True,capture_output=True,env=environment,timeout=240)
  assert result.returncode==expected,(name,result.returncode,result.stdout,result.stderr)
  if isolated:
   calls=trace.read_text()
   assert not re.search(r'\b(socket|connect|sendto|sendmsg|bind|listen|accept|recvfrom|recvmsg)\(',calls),calls
   assert len(re.findall(r'\bexecve\(',calls))==(2 if name=='java-offline' else 1),calls
  return result.stdout
 run('declined',['4',str(app),'no'])
 assert not list(root.glob('.awarely-scan-tools/*.tar.gz'))
 run('npm',['2',str(app),'1','demo',str(root),'1'],isolated=True)
 run('python',['3',str(app),'1','demo',str(root),'1'],expected=3,isolated=True)
 run('java-download',['4',str(app),'yes','java-demo',str(root),'1'])
 run('java-offline',['4',str(app),'yes','java-demo',str(root),'1'],isolated=True)
 for report in root.glob('awarely-results-*/inventory.cdx.json'):
  assert report.stat().st_mode & 0o777==0o600
  assert str(root) not in report.read_text()
  assert json.loads(report.read_text())['components']
 assert not list(root.glob('.awarely-scan-tools/run-*'))
 archive=next(root.glob('.awarely-scan-tools/*.tar.gz'));archive.write_bytes(b'tampered')
 result=run('tampered',['4',str(app)],expected=2)
 print('PASS: guided native/Syft flow, no-consent/no-download, verified cache, offline execution, private output, tamper rejection')
