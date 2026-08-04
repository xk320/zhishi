#!/usr/bin/env python3
"""绑定可信历史现场的成本、流动性与执行输入缺口登记器。"""
from __future__ import annotations
import argparse, csv, datetime as dt, hashlib, json, os, re, shutil, subprocess, tempfile, time
from pathlib import Path
try:
    import resource
except ImportError:
    resource = None

SCRIPT_VERSION = "cost-execution-1.0"
CONFIG_PATH = Path("config/数据/成本执行来源.json")
CONFIG_SHA256 = "26f68554e23bd356b875672f2f4868c0ccdb3d2979123c27522775b2cf56d8aa"
TARGETS = ("BTC", "ETH")
RESULT_COLUMNS = ("验证批次","资产编号","标的","来源成员编号","交易场所","市场类型","精确合约","方向","阶段","主研究尺度","历史时点","可信重放结论","成本来源状态","手续费状态","价差状态","深度状态","冲击状态","资金费率状态","执行延迟状态","可成交量状态","输入数据版本","输入数据哈希","规则版本","代码版本","输入指纹","输出指纹","结论","原因代码","依据","解除条件")
SENSITIVE = re.compile(r"(?i)(?:password|passwd|secret|token|authorization|private key|-----BEGIN|\b\d{1,3}(?:\.\d{1,3}){3}\b)")

def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",",":"), allow_nan=False)
def sha256_bytes(data): return hashlib.sha256(data).hexdigest()
def sha256_path(path): return sha256_bytes(path.read_bytes())
def read_json(path, expected):
    if path.is_symlink() or not path.is_file() or sha256_path(path) != expected: raise ValueError("input_fingerprint_mismatch")
    value=json.loads(path.read_text(encoding="utf-8"));
    if not isinstance(value,dict): raise ValueError("input_json_object_required")
    return value
def config_ok(config):
    if set(config)!={"合同版本","任务编号","允许SSH目标","允许标的","主研究尺度","方向","阶段","输入","资源上限","安全边界"} or config["合同版本"]!="cost-execution-1.0" or config["任务编号"]!="任务-000033": raise ValueError("config_contract_mismatch")
    if tuple(config["允许SSH目标"])!=("ubuntu",) or tuple(config["允许标的"])!=TARGETS or tuple(config["主研究尺度"])!=("4小时","8小时","24小时","48小时") or tuple(config["方向"])!=("做多","做空") or tuple(config["阶段"])!=("入场","退出"): raise ValueError("config_scope_mismatch")
    if config["资源上限"] != {"远端预检超时秒":30,"批次总超时秒":300,"单成员超时秒":30,"最大成员数":1000,"最大输出字节数":16777216,"最大日志字节数":4096,"最大内存字节数":536870912}: raise ValueError("config_resource_mismatch")
    if config["安全边界"] != {"远端读取业务正文":False,"远端落盘":False,"读取账户费率":False,"修改原始数据":False,"生成交易结论":False}: raise ValueError("config_security_mismatch")
    expected_input={"路径":"artifacts/审计/历史现场重放/replay-20260805T013610+0800-4492706a9320/验证清单.json","SHA-256":"2e6d47be39c164f4bdfa1f6b035aac2d9cf951e5a0078423a3efda681ac0d429","结果路径":"artifacts/审计/历史现场重放/replay-20260805T013610+0800-4492706a9320/逐成员结果.csv","结果SHA-256":"c4408bf46e65ba775a0d466ccd9edcf6987643c944eb5cd2198cfee55f418d75"}
    if config["输入"]["可信重放清单"] != expected_input or config["输入"]["任务-000032合并提交"] != "5fce9ee989ad222f716fe9648d8ad1ca3763ecdf" or config["输入"]["成本来源登记"] != {"路径":"artifacts/数据/成本执行/成本来源登记.csv","状态":"未登记"}: raise ValueError("approved_input_identity_mismatch")
def preflight(timeout=30, max_log=4096):
    command=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=5","-o","ConnectionAttempts=1","-o","UserKnownHostsFile=/dev/null","-o","StrictHostKeyChecking=no","ubuntu","python3","-I","-B","-"]
    program="import json,platform; print(json.dumps({'status':'ok','python':platform.python_version(),'runtime':'cost-execution-read-only-preflight'},sort_keys=True))"
    try: result=subprocess.run(command,input=program,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e: raise RuntimeError("remote_preflight_failed") from e
    log=len(result.stderr.encode("utf-8",errors="replace"))
    if log>max_log or result.returncode!=0: raise RuntimeError("remote_preflight_failed")
    try: value=json.loads(result.stdout)
    except (TypeError,ValueError) as e: raise RuntimeError("remote_preflight_invalid_response") from e
    if set(value)!={"status","python","runtime"} or value.get("status")!="ok" or value.get("runtime")!="cost-execution-read-only-preflight": raise RuntimeError("remote_preflight_invalid_response")
    return {"python":str(value["python"]),"runtime":str(value["runtime"]),"status":"ok","日志字节数":log}
def load_members(root, config):
    config_ok(config); spec=config["输入"]["可信重放清单"]; manifest=read_json(root/spec["路径"],spec["SHA-256"]); result_path=root/spec["结果路径"]
    if result_path.is_symlink() or not result_path.is_file() or sha256_path(result_path)!=spec["结果SHA-256"]: raise ValueError("replay_result_fingerprint_mismatch")
    members=manifest.get("候选成员总数"); counts=manifest.get("标的计数"); status=manifest.get("状态计数")
    if members!=630 or counts!={"BTC":315,"ETH":315} or status!={"拒绝":14,"无法判定":616,"通过":0}: raise ValueError("replay_manifest_mismatch")
    with result_path.open(encoding="utf-8") as handle:
        rows=list(csv.DictReader(handle))
    if len(rows)!=630 or {row.get("标的") for row in rows} != set(TARGETS): raise ValueError("replay_members_mismatch")
    return rows, manifest
def build_rows(batch, members, code_sha):
    rows=[]
    for member in sorted(members,key=lambda r:(r["资产编号"],r["标的"],r["来源成员编号"])):
        drift=member["重放结论"]=="拒绝"; conclusion="拒绝" if drift else "无法判定"; reason="input_identity_drift" if drift else "cost_source_missing"
        row={key:"未判定" for key in RESULT_COLUMNS}; row.update({"验证批次":batch,"资产编号":member["资产编号"],"标的":member["标的"],"来源成员编号":member["来源成员编号"],"交易场所":"未判定","市场类型":"未判定","精确合约":"未判定","方向":"未判定","阶段":"未判定","主研究尺度":"未判定（仅允许4小时/8小时/24小时/48小时）","历史时点":"未判定","可信重放结论":member["重放结论"],"成本来源状态":"拒绝（输入身份漂移）" if drift else "无法判定（成本来源未登记）","手续费状态":"拒绝" if drift else "无法判定","价差状态":"拒绝" if drift else "无法判定","深度状态":"拒绝" if drift else "无法判定","冲击状态":"拒绝" if drift else "无法判定","资金费率状态":"拒绝" if drift else "无法判定","执行延迟状态":"拒绝" if drift else "无法判定","可成交量状态":"拒绝" if drift else "无法判定","规则版本":"cost-execution-1.0","代码版本":code_sha,"输入指纹":member["质量证据指纹"],"结论":conclusion,"原因代码":reason,"依据":"任务-000032输入身份漂移，或尚无获批成本来源登记；未读取当前费率/盘口/账户信息","解除条件":"登记带来源、时间、版本、数据截止和可见性证据的手续费、价差、深度、冲击、资金费率、延迟和可成交量；重新发布批次"})
        row["输出指纹"]=sha256_bytes(canonical({k:row[k] for k in RESULT_COLUMNS if k!="输出指纹"}).encode()); rows.append(row)
    return rows
def publish(root,batch,rows,report,checklist,index,max_bytes):
    root.mkdir(parents=True,exist_ok=True); dest=root/batch
    if dest.exists() or dest.is_symlink(): raise ValueError("batch_exists")
    tmp=Path(tempfile.mkdtemp(prefix=f".{batch}.",dir=root))
    try:
        csvp=tmp/"成员结果.csv"; csvp.write_text("",encoding="utf-8")
        with csvp.open("w",encoding="utf-8",newline="") as h:
            w=csv.DictWriter(h,fieldnames=RESULT_COLUMNS,lineterminator="\n"); w.writeheader(); w.writerows(rows)
        rp=tmp/"验证报告.md"; rp.write_text(report,encoding="utf-8")
        checklist=dict(checklist); checklist["成员结果SHA-256"]=sha256_path(csvp); checklist["验证报告SHA-256"]=sha256_path(rp)
        cp=tmp/"验证清单.json"; cp.write_text(canonical(checklist)+"\n",encoding="utf-8")
        if sum(p.stat().st_size for p in (csvp,rp,cp))>max_bytes: raise RuntimeError("output_limit_exceeded")
        os.mkdir(dest)
        for p in tmp.iterdir(): os.replace(p,dest/p.name)
        shutil.rmtree(tmp)
        ip=root/"批次索引.csv"; new=not ip.exists()
        with ip.open("a",encoding="utf-8",newline="") as h:
            w=csv.DictWriter(h,fieldnames=tuple(index),lineterminator="\n");
            if new:w.writeheader()
            w.writerow(index)
        return {"csv_sha":sha256_path(dest/"成员结果.csv"),"report_sha":sha256_path(dest/"验证报告.md"),"checklist_sha":sha256_path(dest/"验证清单.json")}
    except BaseException:
        shutil.rmtree(tmp,ignore_errors=True); raise
def execute(root,config_path,batch_root,batch):
    if config_path.resolve()!=(root/CONFIG_PATH).resolve() or CONFIG_SHA256=="__CONFIG_SHA256__" or sha256_path(config_path)!=CONFIG_SHA256: raise ValueError("config_path_or_fingerprint_mismatch")
    config=json.loads(config_path.read_text(encoding="utf-8")); start=time.monotonic(); resources=config["资源上限"]; members,manifest=load_members(root,config)
    if len(members)>resources["最大成员数"]: raise ValueError("member_limit_exceeded")
    remote=preflight(resources["远端预检超时秒"],resources["最大日志字节数"]); deadline=start+resources["批次总超时秒"]
    if time.monotonic()>deadline: raise RuntimeError("batch_timeout")
    code_sha=sha256_path(Path(__file__).resolve()); rows=build_rows(batch,members,code_sha)
    rss=None
    if resource is not None:
        rss=int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss); rss=rss if os.uname().sysname=="Darwin" else rss*1024
        if rss>resources["最大内存字节数"]: raise RuntimeError("memory_limit_exceeded")
    counts={s:sum(row["结论"]==s for row in rows) for s in ("拒绝","无法判定","失败","未成熟","失效","通过")}
    report=f"# 成本、流动性与执行数据验证\n\n<!-- markdownlint-disable MD013 -->\n\n- 验证器：`{SCRIPT_VERSION}`\n- 验证批次：`{batch}`\n- 可信重放输入：`replay-20260805T013610+0800-4492706a9320`\n- 远端只读预检：通过（Python {remote['python']}；日志{remote['日志字节数']}字节；未读取业务正文）\n- 资源上限：总超时300秒、单成员30秒、成员1000、输出16MiB、日志4096字节、内存512MiB；RSS实测{rss}字节\n\n## 结论\n\n- 候选成员630；BTC315；ETH315；拒绝{counts['拒绝']}；无法判定{counts['无法判定']}；通过0。\n- 手续费、价差、深度、冲击、资金费率、执行延迟和可成交量均无获批历史来源登记；没有读取当前费率、盘口或账户信息。\n- 本批次不计算净成本、胜率、收益、方向、仓位或交易许可。\n\n## 独立标的\n\n| 标的 | 候选 | 拒绝 | 无法判定 | 通过 |\n| --- | ---: | ---: | ---: | ---: |\n| BTC | 315 | {sum(r['结论']=='拒绝' and r['标的']=='BTC' for r in rows)} | {sum(r['结论']=='无法判定' and r['标的']=='BTC' for r in rows)} | 0 |\n| ETH | 315 | {sum(r['结论']=='拒绝' and r['标的']=='ETH' for r in rows)} | {sum(r['结论']=='无法判定' and r['标的']=='ETH' for r in rows)} | 0 |\n\n## 解除条件\n\n登记各成本字段的来源、版本、数据截止、三类时间和可见性合同后，按相同标的、场所、市场、合约、方向、阶段和主研究尺度创建新批次。\n"
    checklist={"合同版本":"cost-execution-1.0","验证器版本":SCRIPT_VERSION,"验证批次":batch,"候选成员总数":630,"标的计数":{"BTC":315,"ETH":315},"状态计数":counts,"可信重放清单SHA-256":sha256_path(root/config["输入"]["可信重放清单"]["路径"]),"代码SHA-256":code_sha,"资源上限":resources,"资源实测":{"本地峰值RSS字节":rss,"批次耗时秒":round(time.monotonic()-start,6),"远端预检日志字节":remote["日志字节数"]},"远端预检":remote,"成本来源登记":"未登记；未创建样例文件","安全声明":{"远端读取业务正文":False,"远端落盘":False,"读取账户费率":False,"原始数据修改":False,"交易结论":False}}
    index={"验证批次":batch,"合同版本":"cost-execution-1.0","候选成员总数":"630","拒绝数":str(counts["拒绝"]),"无法判定数":str(counts["无法判定"]),"通过数":"0","远端预检":"通过","状态":"已发布"}
    artifacts=publish(batch_root,batch,rows,report,checklist,index,resources["最大输出字节数"]); return {"status":"ok","batch":batch,"counts":counts,"remote":remote,"artifacts":artifacts}
def main():
    p=argparse.ArgumentParser(); p.add_argument("--config",type=Path,required=True); p.add_argument("--batch-root",type=Path,required=True); p.add_argument("--ssh-target",required=True); p.add_argument("--batch",required=True); a=p.parse_args()
    if a.ssh_target!="ubuntu" or not re.fullmatch(r"cost-[0-9]{8}T[0-9]{6}[+-][0-9]{4}-[0-9a-f]{12}",a.batch): raise ValueError("argument_contract_invalid")
    print(canonical(execute(Path.cwd(),a.config.resolve(),a.batch_root.resolve(),a.batch))); return 0
if __name__=="__main__":
    try: raise SystemExit(main())
    except (OSError,RuntimeError,ValueError) as e: print(f"成本执行验证失败：{e}"); raise SystemExit(1)
