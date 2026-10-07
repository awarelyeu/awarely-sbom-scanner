"""Exercise installer trust gates and recovery without network or root."""
import hashlib, io, os, re, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path

source = (Path(__file__).resolve().parent / 'install.sh').read_text()
version = re.search(r'^SCAN_VERSION=(.+)$', source, re.M).group(1)

def archive(path, members):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in members.items():
            data = data.encode(); info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o700
            tf.addfile(info, io.BytesIO(data))

def run_case(name, answers, *, bad_hash=False, bad_attestation=False, missing=False):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); home = root/'home'; home.mkdir(); bins = root/'bin'; bins.mkdir(); files = root/'files'; files.mkdir(); scratch=root/'tmp'; scratch.mkdir()
        for tool in ['tar','gzip','awk','mktemp','mkdir','chmod','cat','ln','rm']:
            (bins/tool).symlink_to(shutil.which(tool))
        (bins/'sha256sum').write_text('#!/bin/sh\nexec '+(shutil.which('sha256sum') or shutil.which('shasum')+' -a 256')+' "$@"\n')
        (bins/'sha256sum').chmod(0o700)
        (bins/'uname').write_text('#!/bin/sh\ncase "$1" in -m) echo x86_64;; -s) echo Linux;; esac\n'); (bins/'uname').chmod(0o700)
        verifier='''#!/bin/sh
if [ "$3" = --help ]; then exit 0; fi
[ -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ] || exit 70
case "$*" in *--bundle*--repo*--signer-workflow*--source-ref*) ;; *) exit 71;; esac
printf verified > "$HOME/verifier-ran"
exit '''+('1' if bad_attestation else '0')+'\n'
        gh_archive=files/'gh_2.102.0_linux_amd64.tar.gz'
        archive(gh_archive,{'gh_2.102.0_linux_amd64/bin/gh':verifier,'gh_2.102.0_linux_amd64/LICENSE':'MIT'})
        digest=hashlib.sha256(gh_archive.read_bytes()).hexdigest()
        # Replace only the fixture's expected digest; production pins remain unchanged.
        script=source.replace('bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386', '0'*64 if bad_hash else digest)
        binary='#!/bin/sh\necho awarely-scan '+version+'\n'
        release=files/f'awarely-scan_{version}_linux_amd64.tar.gz'
        archive(release,{'awarely-scan':binary,'SHA256SUMS':hashlib.sha256(binary.encode()).hexdigest()+'  awarely-scan\n'})
        (files/'SHA256SUMS').write_text(hashlib.sha256(release.read_bytes()).hexdigest()+'  '+release.name+'\n')
        (files/(release.name+'.sigstore.jsonl')).write_text('fixture proof checked by fake verifier')
        curl=bins/'curl'; curl.write_text('#!'+sys.executable+'\nimport pathlib,sys,shutil\na=sys.argv; url=next(x for x in a if x.startswith("https://")); shutil.copyfile('+repr(str(files))+'+"/"+url.rsplit("/",1)[1],a[a.index("-o")+1])\n');curl.chmod(0o700)
        installer=root/'install.sh';installer.write_text(script)
        env={**os.environ,'HOME':str(home),'PATH':str(bins),'TMPDIR':str(scratch),'GH_TOKEN':'dummy-must-not-be-used','GITHUB_TOKEN':'dummy-must-not-be-used'}
        if missing:
            saved=root/'curl-saved';curl.rename(saved)
            proc=subprocess.Popen(['/bin/sh',str(installer)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            # Read until the prompt is emitted without a newline, then install the missing fixture tool.
            out=''
            while not out.endswith('Press Enter to check again, or q to quit: '):
                ch=proc.stdout.read(1)
                assert ch, out
                out+=ch
            saved.rename(curl)
            rest,_=proc.communicate(answers,timeout=15);out+=rest;code=proc.returncode
            assert 'MISSING: curl' in out
        else:
            p=subprocess.run(['/bin/sh',str(installer)],input=answers,text=True,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15);out=p.stdout;code=p.returncode
        dest=home/'.local/bin/awarely-scan'
        if bad_hash or bad_attestation or answers=='no\n':
            assert code!=0 and not dest.exists(),out
            if bad_hash or answers=='no\n': assert not (home/'verifier-ran').exists(),out
        else:
            assert code==0 and dest.exists() and (home/'verifier-ran').exists(),out
            assert dest.stat().st_mode & 0o777 == 0o700
        assert not list(scratch.iterdir()),'temporary verifier was not removed'
        print('PASS',name)

run_case('temporary verifier and cleanup','yes\n')
run_case('declined verifier download','no\n')
run_case('tampered verifier rejected before execution','yes\n',bad_hash=True)
run_case('failed provenance never installs scanner','yes\n',bad_attestation=True)
run_case('missing tool corrected in same installer session','\nyes\n',missing=True)
