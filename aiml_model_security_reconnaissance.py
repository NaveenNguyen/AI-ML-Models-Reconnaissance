#!/usr/bin/env python3
"""
AI/ML Model Security Reconnaissance Toolkit
===========================================
Pentester-oriented reconnaissance for common AI/ML model artifacts.

Supported model families:
  computer-vision, language-llm, audio-speech, multimodal, time-series,
  tabular-classical, generative, reinforcement-learning, graph,
  recommendation-ranking, auto

Use --list-model-types for family-specific format guidance.

Safety: this tool does NOT blindly deserialize untrusted pickle/PyTorch objects.
"""
from __future__ import annotations
import argparse, ast, collections, hashlib, json, math, pickletools, platform, re, struct, sys, time, zipfile
from pathlib import Path
from typing import Any

TOOL_NAME = "AI/ML Model Security Reconnaissance Toolkit"
TOOL_VERSION = "3.3"
MODEL_TYPES = {
    "computer-vision": ("Computer Vision", [".onnx", ".pt", ".pth", ".safetensors", ".tflite", ".keras", ".h5", ".hdf5"], "classification, detection, segmentation, pose, depth, OCR"),
    "language-llm": ("Language / LLM", [".safetensors", ".gguf", ".pt", ".pth", ".onnx", ".bin", "SavedModel directory"], "LLMs, encoders, embeddings, text classifiers"),
    "audio-speech": ("Audio / Speech", [".onnx", ".pt", ".pth", ".safetensors", ".tflite", ".keras", ".h5", ".hdf5"], "ASR, speaker recognition, sound classification, TTS"),
    "multimodal": ("Multimodal", [".safetensors", ".gguf", ".pt", ".pth", ".onnx", ".keras"], "vision-language, text-audio, video-language"),
    "time-series": ("Time-Series / Sequential", [".onnx", ".pt", ".pth", ".keras", ".h5", ".hdf5", ".tflite", ".pkl", ".joblib"], "forecasting, anomaly detection, predictive maintenance"),
    "tabular-classical": ("Tabular / Classical ML", [".onnx", ".pkl", ".pickle", ".joblib", ".json", ".ubj", ".txt", ".model"], "scikit-learn, XGBoost, LightGBM, SVM, random forest"),
    "generative": ("Generative", [".safetensors", ".pt", ".pth", ".onnx", ".keras", ".h5", ".hdf5"], "diffusion, GAN, VAE, image/audio generation"),
    "reinforcement-learning": ("Reinforcement Learning", [".pt", ".pth", ".onnx", ".zip", ".pkl", ".joblib"], "policies, actor-critic, Q-networks"),
    "graph": ("Graph Neural Network", [".pt", ".pth", ".onnx", ".safetensors"], "GNNs, graph classification, molecular/network models"),
    "recommendation-ranking": ("Recommendation / Ranking", [".onnx", ".pt", ".pth", ".keras", ".h5", ".hdf5", ".pkl", ".joblib"], "ranking, matching, personalization, recommendation"),
    "auto": ("Automatic / Generic", ["all supported formats"], "generic artifact reconnaissance"),
}
SUFFIX_FORMAT = {
    ".onnx":"onnx", ".pt":"pytorch", ".pth":"pytorch", ".safetensors":"safetensors",
    ".gguf":"gguf", ".tflite":"tflite", ".keras":"keras", ".h5":"keras-h5", ".hdf5":"keras-h5",
    ".pkl":"pickle", ".pickle":"pickle", ".joblib":"joblib", ".json":"xgboost-json",
    ".ubj":"xgboost-ubj", ".txt":"lightgbm-text", ".model":"lightgbm-text", ".zip":"zip", ".bin":"binary"
}

def section(t): print("\n" + "="*96 + "\n" + t + "\n" + "="*96)
def kv(k,v): print(f"{k}: {v}")
def safe(v):
    if v is None or isinstance(v,(str,int,float,bool)): return v
    if isinstance(v,dict): return {str(k):safe(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)): return [safe(x) for x in v]
    return str(v)

def parse_metadata_value(value):
    """Best-effort metadata parser. One malformed value must never abort reconnaissance."""
    if value is None:
        return None, None
    if not isinstance(value, str):
        return value, None
    s=value.strip()
    if not s:
        return value, None
    looks_container = s[0] in "[{('\""
    looks_number = re.fullmatch(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?", s) is not None
    looks_bool_none = s in ("True","False","None")
    if not (looks_container or looks_number or looks_bool_none):
        return value, None
    try:
        return ast.literal_eval(s), None
    except Exception as e:
        return value, f"{type(e).__name__}: {e}"
def hsize(n):
    x=float(n)
    for u in ("B","KB","MB","GB","TB"):
        if x<1024 or u=="TB": return f"{x:.2f} {u}"
        x/=1024
def sha256_file(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def sha256_dir(p):
    h=hashlib.sha256()
    for f in sorted(x for x in p.rglob("*") if x.is_file()):
        h.update(str(f.relative_to(p)).replace("\\","/").encode()); h.update(b"\0"); h.update(sha256_file(f).encode()); h.update(b"\0")
    return h.hexdigest()
def identity(p):
    if p.is_dir():
        n=sum(x.stat().st_size for x in p.rglob("*") if x.is_file())
        return {"path":str(p),"kind":"directory","size_human":hsize(n),"sha256":sha256_dir(p)}
    return {"path":str(p),"kind":"file","extension":p.suffix.lower(),"size_human":hsize(p.stat().st_size),"sha256":sha256_file(p)}
def detect_format(p):
    if p.is_dir() and (p/"saved_model.pb").exists(): return "tensorflow-savedmodel"
    fmt=SUFFIX_FORMAT.get(p.suffix.lower(),"unknown")
    if fmt=="zip":
        try:
            with zipfile.ZipFile(p) as z:
                names=set(z.namelist())
                if "policy.pth" in names or "data" in names or any("pytorch_variables" in x for x in names): return "stable-baselines-zip"
        except: pass
    return fmt

def list_types():
    print(f"{TOOL_NAME} v{TOOL_VERSION}\n")
    for k,(label,fmts,ex) in MODEL_TYPES.items():
        if k=="auto": continue
        print(f"{k:24} {label}\n  Examples: {ex}\n  Formats:  {', '.join(fmts)}\n")
    print("auto                     Automatic / generic reconnaissance")
    print("\nSupport means safe/intended inspection of useful artifact metadata; not full semantic reconstruction for every framework/version.")

def choose_type():
    keys=[k for k in MODEL_TYPES if k!="auto"]
    print("Select model family:")
    for i,k in enumerate(keys,1): print(f"  {i}. {MODEL_TYPES[k][0]} ({k})")
    print(f"  {len(keys)+1}. Automatic / Generic")
    while True:
        try: s=input("Selection: ").strip()
        except EOFError: return "auto"
        if s.isdigit():
            i=int(s)
            if 1<=i<=len(keys): return keys[i-1]
            if i==len(keys)+1: return "auto"
        if s in MODEL_TYPES: return s
        print("Invalid selection")

def supported(model_type,p):
    if model_type=="auto": return True
    token="SavedModel directory" if p.is_dir() else p.suffix.lower()
    return token in MODEL_TYPES[model_type][1]

def np_stats(a,limit=250000):
    import numpy as np
    a=np.asarray(a); out={"shape":list(a.shape),"dtype":str(a.dtype),"elements":int(a.size)}
    if not a.size or not np.issubdtype(a.dtype,np.number): return out
    f=a.reshape(-1)
    if f.size>limit: f=f[::max(1,f.size//limit)][:limit]; out["stats_sampled"]=True
    if np.issubdtype(f.dtype,np.floating):
        out["nan_count_sample"]=int(np.isnan(f).sum()); out["inf_count_sample"]=int(np.isinf(f).sum()); f=f[np.isfinite(f)]
    if f.size:
        x=f.astype(np.float64,copy=False); out.update(min=float(x.min()),max=float(x.max()),mean=float(x.mean()),std=float(x.std()),zero_fraction_sample=float((f==0).sum()/f.size))
    return out

# --- ONNX ---
def onnx_dim(d):
    if getattr(d,"dim_value",0): return int(d.dim_value)
    if getattr(d,"dim_param",""): return str(d.dim_param)
    return "?"
def onnx_vi(v):
    import onnx
    t=v.type.tensor_type; shape=[onnx_dim(d) for d in t.shape.dim] if t.HasField("shape") else []
    try: dt=onnx.TensorProto.DataType.Name(t.elem_type)
    except: dt=str(t.elem_type)
    return {"name":v.name,"dtype":dt,"shape":shape,"dynamic":any(isinstance(x,str) for x in shape)}
def inspect_onnx(p):
    try:
        import onnx
        from onnx import numpy_helper
    except ImportError as e: raise RuntimeError("pip install onnx numpy") from e
    m=onnx.load(str(p),load_external_data=False); g=m.graph
    md={}; metadata_parse_warnings=[]
    for prop in m.metadata_props:
        parsed,warn=parse_metadata_value(prop.value)
        md[prop.key]=parsed
        if warn:
            metadata_parse_warnings.append({"key":prop.key,"raw_value":prop.value,"warning":warn})
    inits={x.name for x in g.initializer}; inputs=[onnx_vi(x) for x in g.input if x.name not in inits]; outputs=[onnx_vi(x) for x in g.output]
    ops=collections.Counter(n.op_type for n in g.node); domains=collections.Counter(n.domain or "ai.onnx" for n in g.node)
    params=bytes_total=nan=inf=0; dtypes=collections.Counter(); ext=[]; largest=[]
    for t in g.initializer:
        elems=math.prod(t.dims) if t.dims else 1; params+=elems; dt=onnx.TensorProto.DataType.Name(t.data_type); dtypes[dt]+=1
        external=t.data_location==onnx.TensorProto.EXTERNAL
        if external: ext.append(t.name)
        item={"name":t.name,"shape":list(t.dims),"dtype":dt,"elements":elems,"external":external}
        if not external:
            try:
                a=numpy_helper.to_array(t); bytes_total+=a.nbytes; st=np_stats(a); item["stats"]=st; nan+=st.get("nan_count_sample",0); inf+=st.get("inf_count_sample",0)
            except Exception as e: item["stats_error"]=str(e)
        largest.append(item)
    try: onnx.checker.check_model(m); checker={"status":"PASS"}
    except Exception as e: checker={"status":"FAIL","error":str(e)}
    class_map=next((md[k] for k in ("names","classes","class_names","labels") if k in md),None)
    qops=sorted(x for x in ops if "Quantize" in x or "Dequantize" in x)
    return {"status":"PASS" if checker.get("status")=="PASS" else "PARTIAL","format":"onnx","metadata_parse_warnings":metadata_parse_warnings,"model_info":{"ir_version":int(m.ir_version),"producer_name":m.producer_name or None,"producer_version":m.producer_version or None,"model_version":int(m.model_version),"opsets":[{"domain":x.domain or "ai.onnx","version":int(x.version)} for x in m.opset_import],"metadata":safe(md)},"interfaces":{"inputs":inputs,"outputs":outputs},"graph":{"node_count":len(g.node),"initializer_count":len(g.initializer),"operator_histogram":dict(ops.most_common()),"domain_histogram":dict(domains.most_common()),"custom_domains":sorted(d for d in domains if d!="ai.onnx"),"nms_embedded":"NonMaxSuppression" in ops,"resize_embedded":"Resize" in ops,"quantization_ops":qops},"weights":{"parameter_count_estimate":int(params),"initializer_size":hsize(int(bytes_total)),"dtype_histogram":dict(dtypes),"external_initializer_count":len(ext),"external_initializer_names":ext[:100],"sampled_nan_count":int(nan),"sampled_inf_count":int(inf),"largest_initializers":sorted(largest,key=lambda x:x.get("elements",0),reverse=True)[:20]},"semantic_metadata":{"class_mapping":safe(class_map),"task":safe(md.get("task")),"image_size":safe(md.get("imgsz")),"stride":safe(md.get("stride"))},"validation":{"onnx_checker":checker},"external_dependencies":ext}
def ort_dtype(t):
    import numpy as np
    return {"tensor(float)":np.float32,"tensor(float16)":np.float16,"tensor(double)":np.float64,"tensor(int64)":np.int64,"tensor(int32)":np.int32,"tensor(int16)":np.int16,"tensor(int8)":np.int8,"tensor(uint64)":np.uint64,"tensor(uint32)":np.uint32,"tensor(uint16)":np.uint16,"tensor(uint8)":np.uint8,"tensor(bool)":np.bool_}.get(t)
def profile_onnx(p,runs):
    try:
        import numpy as np, onnxruntime as ort
    except ImportError: return {"status":"SKIPPED","reason":"pip install onnxruntime numpy"}
    try: s=ort.InferenceSession(str(p),providers=["CPUExecutionProvider"])
    except Exception as e: return {"status":"FAIL_SESSION_CREATE","error":str(e)}
    rng=np.random.default_rng(2026); lat=[]; outstats=None
    for _ in range(max(1,runs)):
        feed={}
        for inp in s.get_inputs():
            dt=ort_dtype(inp.type); shape=[x if isinstance(x,int) and x>0 else 1 for x in inp.shape]
            if dt is None or math.prod(shape)>25000000: return {"status":"SKIPPED","reason":f"unsupported/oversized {inp.name}: {inp.type} {shape}"}
            if np.issubdtype(dt,np.floating): a=rng.random(shape,dtype=np.float32).astype(dt)
            elif np.issubdtype(dt,np.integer): a=rng.integers(0,2,size=shape,dtype=dt)
            else: a=rng.integers(0,2,size=shape).astype(dt)
            feed[inp.name]=a
        t=time.perf_counter(); outs=s.run(None,feed); lat.append((time.perf_counter()-t)*1000)
        if outstats is None: outstats=[{"min":math.inf,"max":-math.inf,"nan":0,"inf":0} for _ in outs]
        for i,a in enumerate(outs):
            a=np.asarray(a)
            if np.issubdtype(a.dtype,np.floating): outstats[i]["nan"]+=int(np.isnan(a).sum()); outstats[i]["inf"]+=int(np.isinf(a).sum()); f=a[np.isfinite(a)]
            else: f=a.reshape(-1)
            if f.size: outstats[i]["min"]=min(outstats[i]["min"],float(f.min())); outstats[i]["max"]=max(outstats[i]["max"],float(f.max()))
    return {"status":"COMPLETED","providers":s.get_providers(),"runs":len(lat),"latency_ms":{"min":round(min(lat),3),"max":round(max(lat),3),"mean":round(sum(lat)/len(lat),3)},"outputs":[{"index":i,"observed_min":None if x["min"]==math.inf else x["min"],"observed_max":None if x["max"]==-math.inf else x["max"],"nan_count":x["nan"],"inf_count":x["inf"]} for i,x in enumerate(outstats or [])]}
def fingerprint_onnx(p):
    import onnx
    m=onnx.load(str(p),load_external_data=False); g=m.graph; inits={x.name for x in g.initializer}
    payload={"ir":int(m.ir_version),"opsets":sorted([(x.domain or "ai.onnx",int(x.version)) for x in m.opset_import]),"inputs":[onnx_vi(x) for x in g.input if x.name not in inits],"outputs":[onnx_vi(x) for x in g.output],"ops":dict(sorted(collections.Counter(n.op_type for n in g.node).items())),"domains":dict(sorted(collections.Counter(n.domain or "ai.onnx" for n in g.node).items())),"node_count":len(g.node),"initializer_count":len(g.initializer),"initializers":sorted([{"name":t.name,"shape":list(t.dims),"dtype":int(t.data_type)} for t in g.initializer],key=lambda x:x["name"])}
    raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode(); return {"status":"PASS","structural_sha256":hashlib.sha256(raw).hexdigest(),"summary":payload}

# --- PyTorch / safe pickle family ---
def flatten_tensors(obj,prefix=""):
    import torch
    if isinstance(obj,torch.Tensor): yield prefix or "<root>",obj
    elif isinstance(obj,dict):
        for k,v in obj.items(): yield from flatten_tensors(v,f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj,(list,tuple)):
        for i,v in enumerate(obj): yield from flatten_tensors(v,f"{prefix}[{i}]")
def inspect_pytorch(p):
    rep={"format":"pytorch","container":{"is_zip_container":zipfile.is_zipfile(p)}}
    if rep["container"]["is_zip_container"]:
        with zipfile.ZipFile(p) as z:
            names=z.namelist(); rep["container"].update(archive_member_count=len(names),contains_data_pkl=any(x.endswith("data.pkl") for x in names),contains_code=any("/code/" in x or x.startswith("code/") for x in names),archive_members=names[:100])
    try: import torch
    except ImportError: rep["safe_load"]={"status":"SKIPPED","reason":"pip install torch"}; return rep
    try: obj=torch.load(str(p),map_location="cpu",weights_only=True)
    except TypeError: rep["safe_load"]={"status":"SKIPPED","reason":"upgrade PyTorch; weights_only=True unavailable; unsafe fallback disabled"}; return rep
    except Exception as e: rep["safe_load"]={"status":"FAILED_SAFE_LOAD","error":str(e),"note":"unsafe fallback disabled"}; return rep
    tensors=[]; params=bytes_total=0; dtypes=collections.Counter()
    for name,t in flatten_tensors(obj):
        elems=int(t.numel()); params+=elems; bytes_total+=int(t.element_size()*elems); dtypes[str(t.dtype)]+=1
        item={"name":name,"shape":list(t.shape),"dtype":str(t.dtype),"elements":elems}
        try:
            f=t.detach().cpu().reshape(-1)
            if f.numel()>250000: f=f[::max(1,f.numel()//250000)][:250000]
            if torch.is_floating_point(f): item["nan_count_sample"]=int(torch.isnan(f).sum()); item["inf_count_sample"]=int(torch.isinf(f).sum())
        except Exception as e: item["stats_error"]=str(e)
        tensors.append(item)
    meta={}
    if isinstance(obj,dict):
        for k,v in list(obj.items())[:100]: meta[str(k)]=v if isinstance(v,(str,int,float,bool,type(None))) else f"<{type(v).__name__}>"
    rep.update(safe_load={"status":"PASS","top_level_type":type(obj).__name__,"top_level_metadata":meta},weights={"parameter_count_estimate":params,"tensor_count":len(tensors),"tensor_size":hsize(bytes_total),"dtype_histogram":dict(dtypes),"largest_tensors":sorted(tensors,key=lambda x:x.get("elements",0),reverse=True)[:20]})
    return rep
DANGEROUS_PICKLE={"GLOBAL","STACK_GLOBAL","REDUCE","BUILD","INST","OBJ","NEWOBJ","NEWOBJ_EX","EXT1","EXT2","EXT4","PERSID","BINPERSID"}
def inspect_pickle_static(p,fmt):
    rep={"format":fmt,"status":"STATIC_ONLY"}; findings=collections.Counter(); globals_seen=[]
    try:
        data=p.read_bytes()[:64*1024*1024]
        for op,arg,pos in pickletools.genops(data):
            if op.name in DANGEROUS_PICKLE: findings[op.name]+=1
            if op.name=="GLOBAL" and arg: globals_seen.append(str(arg))
        rep.update(security_sensitive_opcodes=dict(findings),referenced_globals=globals_seen[:200],unsafe_deserialization_risk=bool(findings),note="These opcodes do not prove maliciousness; they show why provenance/sandboxing matter. No deserialization was performed.")
    except Exception as e: rep.update(static_parse_error=str(e),unsafe_deserialization_risk=True,note="Artifact was NOT deserialized; treat unknown pickle/joblib as potentially executable.")
    return rep

# --- Safetensors ---
def inspect_safetensors(p):
    rep={"format":"safetensors"}
    try: from safetensors import safe_open
    except ImportError: return {**rep,"status":"SKIPPED","reason":"pip install safetensors"}
    tensors=[]; params=0
    with safe_open(str(p),framework="np") as f:
        md=f.metadata() or {}
        for k in f.keys():
            a=f.get_tensor(k); elems=int(a.size); params+=elems; tensors.append({"name":k,"shape":list(a.shape),"dtype":str(a.dtype),"elements":elems,"stats":np_stats(a)})
    rep.update(status="PASS",metadata=safe(md),weights={"tensor_count":len(tensors),"parameter_count_estimate":params,"largest_tensors":sorted(tensors,key=lambda x:x["elements"],reverse=True)[:20]}); return rep

# --- GGUF metadata ---
def ru32(f): return struct.unpack("<I",f.read(4))[0]
def ru64(f): return struct.unpack("<Q",f.read(8))[0]
def gstr(f):
    n=ru64(f)
    if n>10000000: raise ValueError("unreasonable GGUF string length")
    return f.read(n).decode("utf-8",errors="replace")
def gval(f,t,depth=0):
    if depth>4: raise ValueError("GGUF nesting too deep")
    if t==0:return struct.unpack("<B",f.read(1))[0]
    if t==1:return struct.unpack("<b",f.read(1))[0]
    if t==2:return struct.unpack("<H",f.read(2))[0]
    if t==3:return struct.unpack("<h",f.read(2))[0]
    if t==4:return struct.unpack("<I",f.read(4))[0]
    if t==5:return struct.unpack("<i",f.read(4))[0]
    if t==6:return struct.unpack("<f",f.read(4))[0]
    if t==7:return bool(struct.unpack("<B",f.read(1))[0])
    if t==8:return gstr(f)
    if t==10:return struct.unpack("<Q",f.read(8))[0]
    if t==11:return struct.unpack("<q",f.read(8))[0]
    if t==12:return struct.unpack("<d",f.read(8))[0]
    if t==9:
        subtype=ru32(f); n=ru64(f)
        if n>100000: return f"<large array x {n}, skipped>"
        return [gval(f,subtype,depth+1) for _ in range(n)]
    raise ValueError(f"unknown GGUF type {t}")
def inspect_gguf(p):
    rep={"format":"gguf"}
    try:
        with p.open("rb") as f:
            if f.read(4)!=b"GGUF": return {**rep,"status":"FAIL","error":"invalid GGUF magic"}
            ver=ru32(f); tensor_count=ru64(f); kv_count=ru64(f); md={}
            for _ in range(kv_count): md[gstr(f)]=gval(f,ru32(f))
        interesting={k:v for k,v in md.items() if any(x in k.lower() for x in ("architecture","name","context","embedding","block_count","attention","tokenizer","bos_token","eos_token","rope","quantization","file_type"))}
        rep.update(status="PASS",version=ver,tensor_count=tensor_count,metadata_count=kv_count,interesting_metadata=safe(interesting),metadata_keys=sorted(md)[:300])
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep

# --- TFLite / Keras / SavedModel ---
def inspect_tflite(p):
    rep={"format":"tflite"}; Interpreter=None
    try:
        from tflite_runtime.interpreter import Interpreter
    except Exception:
        try: from tensorflow.lite import Interpreter
        except Exception: return {**rep,"status":"SKIPPED","reason":"install tensorflow or tflite-runtime"}
    try:
        i=Interpreter(model_path=str(p)); i.allocate_tensors()
        def conv(x): return {"name":x.get("name"),"shape":[int(v) for v in x.get("shape",[])],"shape_signature":[int(v) for v in x.get("shape_signature",[])] if x.get("shape_signature") is not None else None,"dtype":str(x.get("dtype")),"quantization":safe(x.get("quantization"))}
        rep.update(status="PASS",interfaces={"inputs":[conv(x) for x in i.get_input_details()],"outputs":[conv(x) for x in i.get_output_details()]})
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep
def inspect_keras(p,fmt):
    rep={"format":fmt}
    if fmt=="keras":
        try:
            with zipfile.ZipFile(p) as z:
                names=z.namelist(); rep["archive_members"]=names[:200]
                if "config.json" in names:
                    c=json.loads(z.read("config.json")); rep["config_summary"]={k:c.get(k) for k in ("class_name","module","registered_name")}
                if "metadata.json" in names: rep["metadata"]=json.loads(z.read("metadata.json"))
                rep["status"]="PASS"
        except Exception as e: rep.update(status="FAIL",error=str(e))
        return rep
    try: import h5py
    except ImportError: return {**rep,"status":"SKIPPED","reason":"pip install h5py"}
    try:
        with h5py.File(p,"r") as f:
            datasets=[]
            def visit(name,obj):
                if isinstance(obj,h5py.Dataset): datasets.append({"name":name,"shape":list(obj.shape),"dtype":str(obj.dtype)})
            f.visititems(visit); attrs={k:(v.decode() if isinstance(v,bytes) else safe(v.tolist() if hasattr(v,"tolist") else v)) for k,v in f.attrs.items()}
            rep.update(status="PASS",root_attributes=attrs,dataset_count=len(datasets),largest_datasets=sorted(datasets,key=lambda x:math.prod(x["shape"]) if x["shape"] else 1,reverse=True)[:30])
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep
def inspect_savedmodel(p):
    files=[str(x.relative_to(p)).replace("\\","/") for x in p.rglob("*") if x.is_file()]
    return {"format":"tensorflow-savedmodel","status":"PASS","files":files[:300],"variables":[x for x in files if x.startswith("variables/")],"assets":[x for x in files if x.startswith("assets/")],"note":"Static inventory only; full signatures require controlled TensorFlow loading."}

# --- Classical / archive ---
def inspect_xgb_json(p):
    rep={"format":"xgboost-json"}
    try:
        o=json.loads(p.read_text(encoding="utf-8")); l=o.get("learner",{}) if isinstance(o,dict) else {}
        rep.update(status="PASS",top_level_keys=list(o)[:100] if isinstance(o,dict) else [],learner_keys=list(l)[:100] if isinstance(l,dict) else [],objective=safe(l.get("objective")),learner_model_param=safe(l.get("learner_model_param")),gradient_booster_type=(l.get("gradient_booster",{}).get("name") if isinstance(l.get("gradient_booster"),dict) else None))
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep
def inspect_lgbm(p):
    rep={"format":"lightgbm-text"}
    try:
        lines=p.read_text(encoding="utf-8",errors="replace").splitlines(); hdr={}; trees=0
        for line in lines[:5000]:
            if line.startswith("Tree="): trees+=1
            if "=" in line:
                k,v=line.split("=",1)
                if k in {"version","num_class","num_tree_per_iteration","label_index","max_feature_idx","objective","feature_names","feature_infos"}: hdr[k]=v[:5000]
        rep.update(status="PASS",header=hdr,observed_tree_headers=trees,line_count=len(lines))
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep
def inspect_zip(p,fmt):
    rep={"format":fmt}
    try:
        with zipfile.ZipFile(p) as z:
            infos=z.infolist(); rep.update(status="PASS",member_count=len(infos),total_uncompressed_bytes=sum(x.file_size for x in infos),members=[{"name":x.filename,"size":x.file_size,"compressed":x.compress_size} for x in infos[:300]],suspicious_paths=[x.filename for x in infos if "../" in x.filename or x.filename.startswith(("/","\\"))][:100])
    except Exception as e: rep.update(status="FAIL",error=str(e))
    return rep

def inspect_artifact(p,fmt):
    if fmt=="onnx": return inspect_onnx(p)
    if fmt=="pytorch": return inspect_pytorch(p)
    if fmt=="safetensors": return inspect_safetensors(p)
    if fmt=="gguf": return inspect_gguf(p)
    if fmt=="tflite": return inspect_tflite(p)
    if fmt in ("keras","keras-h5"): return inspect_keras(p,fmt)
    if fmt=="tensorflow-savedmodel": return inspect_savedmodel(p)
    if fmt in ("pickle","joblib"): return inspect_pickle_static(p,fmt)
    if fmt=="xgboost-json": return inspect_xgb_json(p)
    if fmt=="lightgbm-text": return inspect_lgbm(p)
    if fmt in ("stable-baselines-zip","zip"): return inspect_zip(p,fmt)
    return {"format":fmt,"status":"INVENTORY_ONLY","note":"No safe semantic parser enabled; hash/integrity evidence still captured."}

# --- Companion configs / family guidance ---
def companion_files(p,model_type):
    parent=p if p.is_dir() else p.parent
    patterns=[]
    if model_type in ("language-llm","multimodal","generative"): patterns=["config.json","generation_config.json","tokenizer.json","tokenizer_config.json","special_tokens_map.json","preprocessor_config.json","processor_config.json","adapter_config.json","adapter_model.safetensors","*.index.json"]
    elif model_type=="computer-vision": patterns=["config.json","preprocessor_config.json","classes.txt","labels.txt","*.yaml","*.yml"]
    elif model_type=="audio-speech": patterns=["config.json","preprocessor_config.json","tokenizer.json","vocab.json","feature_extractor*.json"]
    elif model_type in ("time-series","tabular-classical","recommendation-ranking"): patterns=["config.json","schema.json","features.json","preprocessor*"]
    out=[]
    for pat in patterns:
        for x in parent.glob(pat):
            if x.is_file() and x.resolve()!=p.resolve(): out.append(str(x))
    return sorted(set(out))[:200]
def parse_companions(files):
    out={"files":files,"parsed":{}}
    interesting={"model_type","architectures","hidden_size","num_hidden_layers","num_attention_heads","num_key_value_heads","max_position_embeddings","vocab_size","bos_token_id","eos_token_id","pad_token_id","torch_dtype","quantization_config","chat_template","rope_scaling","image_size","num_channels","id2label","label2id","sampling_rate","feature_size","num_mel_bins","base_model_name_or_path","peft_type","task_type"}
    for s in files:
        p=Path(s)
        if p.suffix.lower()!=".json": continue
        try: o=json.loads(p.read_text(encoding="utf-8"))
        except: continue
        if isinstance(o,dict):
            d={k:(o[k][:1000] if k=="chat_template" and isinstance(o[k],str) else safe(o[k])) for k in interesting if k in o}
            if d: out["parsed"][str(p)]=d
    return out

def _class_map_to_dict(class_map):
    if isinstance(class_map, dict):
        out={}
        for k,v in class_map.items():
            try: out[int(k)]=str(v)
            except Exception: pass
        return out
    if isinstance(class_map, (list,tuple)):
        return {i:str(v) for i,v in enumerate(class_map)}
    return {}

def _infer_cv_input_layout(input_info):
    shape=input_info.get("shape",[])
    if len(shape)!=4: return None
    if shape[1] in (1,3,4): return "NCHW"
    if shape[-1] in (1,3,4): return "NHWC"
    return None

def _resolve_cv_hw(input_info):
    shape=input_info.get("shape",[])
    layout=_infer_cv_input_layout(input_info)
    if len(shape)!=4 or layout is None: return None
    h,w=(shape[2],shape[3]) if layout=="NCHW" else (shape[1],shape[2])
    if not isinstance(h,int) or not isinstance(w,int) or h<=0 or w<=0: return None
    return int(h),int(w)

def _letterbox_pil(img,target_w,target_h,fill=(114,114,114)):
    from PIL import Image
    src_w,src_h=img.size
    scale=min(target_w/src_w,target_h/src_h)
    new_w=max(1,round(src_w*scale)); new_h=max(1,round(src_h*scale))
    resized=img.resize((new_w,new_h),Image.Resampling.BILINEAR)
    canvas=Image.new("RGB",(target_w,target_h),fill)
    left=(target_w-new_w)//2; top=(target_h-new_h)//2
    canvas.paste(resized,(left,top))
    return canvas,{"mode":"letterbox","scale":scale,"resized":[new_w,new_h],"pad_left":left,"pad_top":top}

def prepare_cv_image_tensor(image_path,input_info,model_info,resize_mode="auto",channel_order="rgb",input_scale="auto"):
    try:
        import numpy as np
        from PIL import Image
    except ImportError as e:
        raise RuntimeError("Real-image inference requires Pillow and NumPy: pip install pillow numpy") from e

    hw=_resolve_cv_hw(input_info)
    if not hw:
        raise RuntimeError(f"Cannot infer fixed image H/W from input shape {input_info.get('shape')}")
    target_h,target_w=hw
    layout=_infer_cv_input_layout(input_info)
    img=Image.open(image_path).convert("RGB")
    original_size=list(img.size)

    metadata=model_info.get("metadata",{}) if isinstance(model_info,dict) else {}
    producer=" ".join(str(metadata.get(k,"")) for k in ("author","description","task","head")).lower()
    if resize_mode=="auto":
        resize_mode="letterbox" if "ultralytics" in producer or metadata.get("task")=="detect" else "stretch"

    if resize_mode=="letterbox":
        processed,transform=_letterbox_pil(img,target_w,target_h)
    else:
        processed=img.resize((target_w,target_h),Image.Resampling.BILINEAR)
        transform={"mode":"stretch","resized":[target_w,target_h]}

    arr=np.asarray(processed)
    if channel_order=="bgr":
        arr=arr[...,::-1]

    dtype_name=str(input_info.get("dtype","FLOAT")).upper()
    dtype_map={
        "FLOAT":np.float32,"FLOAT16":np.float16,"DOUBLE":np.float64,
        "UINT8":np.uint8,"INT8":np.int8,"INT32":np.int32,"INT64":np.int64
    }
    dtype=dtype_map.get(dtype_name,np.float32)

    scale_applied="none"
    if np.issubdtype(dtype,np.floating):
        arr=arr.astype(dtype)
        if input_scale=="auto" or input_scale=="0-1":
            arr=arr/np.array(255.0,dtype=dtype); scale_applied="0-1"
        elif input_scale=="0-255":
            scale_applied="0-255"
    else:
        arr=arr.astype(dtype); scale_applied="0-255"

    if layout=="NCHW":
        arr=np.transpose(arr,(2,0,1))
    arr=np.expand_dims(arr,0)

    return arr,{
        "image":str(Path(image_path).resolve()),
        "original_size_wh":original_size,
        "target_size_hw":[target_h,target_w],
        "layout":layout,
        "channel_order":channel_order.upper(),
        "input_scale":scale_applied,
        "transform":transform,
        "tensor_stats":np_stats(arr),
        "note":"Preprocessing is a tester-selected/reference assumption; confirm against production/reference code."
    }

def interpret_cv_output(outputs,inspection,top_k=10):
    import numpy as np
    result={"status":"HEURISTIC","outputs":[]}
    class_map=_class_map_to_dict(inspection.get("semantic_metadata",{}).get("class_mapping"))
    class_count=len(class_map)

    for oi,out in enumerate(outputs):
        a=np.asarray(out)
        item={"output_index":oi,"shape":list(a.shape),"dtype":str(a.dtype),"stats":np_stats(a,500000)}
        if a.ndim==3 and a.shape[0]==1 and class_count:
            expected=4+class_count
            if a.shape[1]==expected:
                pred=a[0].T
                item["layout_hint"]="[candidates, 4 + classes]"
            elif a.shape[2]==expected:
                pred=a[0]
                item["layout_hint"]="[candidates, 4 + classes]"
            else:
                pred=None

            if pred is not None and pred.shape[1]>=expected:
                cls=pred[:,4:4+class_count]
                best_ids=np.argmax(cls,axis=1)
                best_scores=cls[np.arange(cls.shape[0]),best_ids]
                order=np.argsort(best_scores)[::-1][:max(1,int(top_k))]
                candidates=[]
                for idx in order:
                    cid=int(best_ids[idx])
                    candidates.append({
                        "candidate_index":int(idx),
                        "class_id":cid,
                        "class_name":class_map.get(cid,str(cid)),
                        "raw_score":float(best_scores[idx]),
                        "box_raw_4":[float(x) for x in pred[idx,:4]],
                    })
                item["detector_interpretation"]={
                    "candidate_count":int(pred.shape[0]),
                    "class_count":class_count,
                    "assumption":"First 4 channels are box values; remaining channels are class scores; no separate objectness assumed.",
                    "top_candidates":candidates,
                }
        result["outputs"].append(item)
    return result

def run_real_image_inference(model_path,image_path,inspection,top_k=10,resize_mode="auto",channel_order="rgb",input_scale="auto",dump_raw_output=None):
    try:
        import numpy as np
        import onnxruntime as ort
    except ImportError:
        return {"status":"SKIPPED","reason":"Install onnxruntime numpy"}

    inputs=inspection.get("interfaces",{}).get("inputs",[])
    if len(inputs)!=1:
        return {"status":"SKIPPED","reason":f"Real-image helper currently expects exactly one model input; found {len(inputs)}."}

    try:
        tensor,prep=prepare_cv_image_tensor(
            image_path,inputs[0],inspection.get("model_info",{}),
            resize_mode=resize_mode,channel_order=channel_order,input_scale=input_scale
        )
        session=ort.InferenceSession(str(model_path),providers=["CPUExecutionProvider"])
        input_name=session.get_inputs()[0].name
        start=time.perf_counter()
        outputs=session.run(None,{input_name:tensor})
        latency_ms=(time.perf_counter()-start)*1000.0

        dump_path=None
        if dump_raw_output:
            dump_path=str(Path(dump_raw_output).expanduser().resolve())
            Path(dump_path).parent.mkdir(parents=True,exist_ok=True)
            np.savez_compressed(dump_path,**{f"output_{i}":o for i,o in enumerate(outputs)})

        return {
            "status":"PASS",
            "latency_ms":round(latency_ms,3),
            "preprocessing":prep,
            "raw_outputs":[{"index":i,"shape":list(o.shape),"dtype":str(o.dtype),"stats":np_stats(o,500000)} for i,o in enumerate(outputs)],
            "interpretation":interpret_cv_output(outputs,inspection,top_k=top_k),
            "raw_output_dump":dump_path,
        }
    except Exception as e:
        return {"status":"FAIL","error":str(e)}

def security_observations(r):
    ins=r.get("inspection",{})
    obs=[]
    def add(level,msg): obs.append({"level":level,"message":msg})
    if ins.get("status")=="ERROR":
        add("FAIL","Format-specific reconnaissance failed; treat this report as partial.")
        return obs

    if ins.get("format")=="onnx":
        val=ins.get("validation",{}).get("onnx_checker",{})
        add("PASS" if val.get("status")=="PASS" else "WARN",
            "ONNX structural checker passed." if val.get("status")=="PASS" else "ONNX structural checker did not pass.")
        g=ins.get("graph",{})
        add("PASS" if not g.get("custom_domains") else "WARN",
            "No custom ONNX operator domains detected." if not g.get("custom_domains") else f"Custom ONNX domains detected: {g.get('custom_domains')}")
        add("INFO","NMS is embedded in the model graph." if g.get("nms_embedded") else "NMS appears external; decoder/NMS becomes an L2 trust boundary.")
        add("INFO","Resize exists in the graph." if g.get("resize_embedded") else "Resize appears external; verify preprocessing equivalence.")
        w=ins.get("weights",{})
        add("PASS" if not w.get("sampled_nan_count") and not w.get("sampled_inf_count") else "WARN",
            "No NaN/Inf found in sampled weights." if not w.get("sampled_nan_count") and not w.get("sampled_inf_count") else
            f"Sampled weights contain NaN/Inf (NaN={w.get('sampled_nan_count')}, Inf={w.get('sampled_inf_count')}).")
        add("PASS" if not w.get("external_initializer_count") else "INFO",
            "No external ONNX initializer files referenced." if not w.get("external_initializer_count") else
            f"{w.get('external_initializer_count')} external initializer(s) referenced; include them in integrity controls.")
        inputs=ins.get("interfaces",{}).get("inputs",[])
        if inputs:
            dynamic=any(x.get("dynamic") for x in inputs)
            add("INFO","Dynamic input dimensions detected; include dimension/resource stress tests." if dynamic else "Input dimensions are static.")
        q=g.get("quantization_ops",[])
        add("INFO",f"Quantization operators detected: {q}" if q else "No ONNX QuantizeLinear/DequantizeLinear operators detected.")
        if ins.get("metadata_parse_warnings"):
            add("WARN",f"{len(ins['metadata_parse_warnings'])} metadata value(s) retained as raw strings after safe parse fallback.")

    if r.get("real_image_inference"):
        ri=r["real_image_inference"]
        add("PASS" if ri.get("status")=="PASS" else "WARN",
            "Real-image forward pass completed." if ri.get("status")=="PASS" else f"Real-image forward pass failed/skipped: {ri.get('error') or ri.get('reason')}")
    return obs

def important_summary(r):
    ins=r.get("inspection",{})
    out=[]
    if ins.get("format")=="onnx":
        mi=ins.get("model_info",{}); sem=ins.get("semantic_metadata",{}); g=ins.get("graph",{}); w=ins.get("weights",{})
        out.append(("Model", f"{mi.get('producer_name') or 'Unknown producer'} | ONNX opset {', '.join(str(x.get('version')) for x in mi.get('opsets',[])) or '?'}"))
        if sem.get("task"): out.append(("Task",str(sem.get("task"))))
        inputs=ins.get("interfaces",{}).get("inputs",[]); outputs=ins.get("interfaces",{}).get("outputs",[])
        if inputs: out.append(("Input",", ".join(f"{x.get('name')} {x.get('dtype')} {x.get('shape')}" for x in inputs)))
        if outputs: out.append(("Output",", ".join(f"{x.get('name')} {x.get('dtype')} {x.get('shape')}" for x in outputs)))
        cmap=_class_map_to_dict(sem.get("class_mapping"))
        if cmap: out.append(("Classes",f"{len(cmap)} classes"))
        out.append(("Graph",f"{g.get('node_count')} nodes | {g.get('initializer_count')} initializers | {w.get('parameter_count_estimate',0):,} parameters"))
        out.append(("Postprocess","NMS embedded" if g.get("nms_embedded") else "NMS external / not detected"))
        out.append(("Custom ops",str(g.get("custom_domains") or "None")))
        out.append(("Quantization",str(g.get("quantization_ops") or "None detected")))
    return out

def family_hints(rep,model_type):
    hints=[]
    if model_type=="computer-vision":
        if rep.get("format")=="onnx":
            ins=rep.get("interfaces",{}).get("inputs",[])
            if ins and len(ins[0].get("shape",[]))==4:
                s=ins[0]["shape"]
                if s[1] in (1,3,4): hints.append(f"Likely NCHW image input from shape {s}.")
                elif s[-1] in (1,3,4): hints.append(f"Likely NHWC image input from shape {s}.")
            if not rep.get("graph",{}).get("nms_embedded",False): hints.append("NMS appears external; inspect decoder/postprocessing as a separate trust boundary.")
            if not rep.get("graph",{}).get("resize_embedded",False): hints.append("Resize appears external; verify reference vs production preprocessing.")
    elif model_type=="language-llm": hints += ["Treat tokenizer, config, chat template, generation config and adapters as part of the model trust boundary.","Runtime attack surfaces include context-length abuse, prompt/instruction hierarchy, tools/plugins and RAG boundaries."]
    elif model_type=="multimodal": hints.append("Treat processors/tokenizers/vision encoders/projectors and cross-modal prompt handling as separate trust boundaries.")
    elif model_type=="audio-speech": hints.append("Verify sample rate, channels, feature extraction and decoder/tokenizer assumptions.")
    elif model_type=="time-series": hints.append("Verify windowing, sequence length, timestamp order, missing-value handling and normalization.")
    elif model_type=="tabular-classical": hints.append("Feature order, scaler/encoder and categorical preprocessing are security-relevant companion artifacts.")
    elif model_type=="generative": hints.append("Schedulers, VAEs, text encoders, LoRA/adapters and safety filters may be separate artifacts.")
    elif model_type=="reinforcement-learning": hints.append("Observation/action spaces, reward pipeline and environment wrappers are as important as policy weights.")
    elif model_type=="graph": hints.append("Graph construction, adjacency normalization and feature schema are preprocessing attack surfaces.")
    elif model_type=="recommendation-ranking": hints.append("Feature schema, embeddings, candidate generation and ranking stages are separate trust boundaries.")
    return hints

def attack_surface(rep,model_type):
    s=[{"surface":"Artifact integrity / provenance","why":"Model replacement, downgrade, poisoned dependency or unauthorized artifact changes break the trust chain.","tests":["compare approved hash","verify signature/authenticity","verify version/lineage","review update path"]}]
    if rep.get("format") in ("pytorch","pickle","joblib"): s.append({"surface":"Unsafe deserialization","why":"Pickle-family formats may execute code under unsafe loading APIs.","tests":["static opcode scan","sandbox handling","avoid unsafe load","verify source trust"]})
    if rep.get("interfaces"): s.append({"surface":"Model input/output boundary","why":"Shape, dtype, values, sequence length and dimensional assumptions are fuzzable.","tests":["wrong shape","wrong dtype","NaN/Inf","empty/oversized input","unexpected batch/sequence size"]})
    domain={"computer-vision":["preprocessing equivalence","class mapping","adversarial image/patch","decoder/NMS abuse"],"language-llm":["tokenizer mismatch","context-length abuse","prompt injection","system-prompt leakage","tool/RAG boundary review"],"audio-speech":["sample-rate/channel mismatch","malformed audio","adversarial audio","decoder/tokenizer boundary"],"multimodal":["cross-modal injection","modality mismatch","image-text prompt injection","processor/config integrity"],"time-series":["sequence length","timestamp disorder","missing values","sensor replay","drift/outlier handling"],"tabular-classical":["feature order/type mismatch","missing/NaN values","out-of-range values","preprocessor/model mismatch"],"generative":["scheduler/config mismatch","conditioning abuse","latent/input bounds","model/LoRA replacement"],"reinforcement-learning":["observation bounds","action bounds","reward manipulation","policy replacement","environment poisoning"],"graph":["node/edge extremes","malformed adjacency","feature mismatch","graph poisoning"],"recommendation-ranking":["feature/embedding mismatch","candidate explosion","ranking manipulation","profile poisoning"]}
    if model_type in domain: s.append({"surface":MODEL_TYPES[model_type][0]+" semantic attack surface","why":"Family-specific preprocessing/state/orchestration assumptions can be security-relevant.","tests":domain[model_type]})
    return s

def compare(p1,p2):
    out={"primary_format":detect_format(p1),"other_format":detect_format(p2),"primary_sha256":sha256_file(p1) if p1.is_file() else sha256_dir(p1),"other_sha256":sha256_file(p2) if p2.is_file() else sha256_dir(p2)}; out["byte_identical"]=out["primary_sha256"]==out["other_sha256"]
    if out["primary_format"]==out["other_format"]=="onnx":
        a,b=fingerprint_onnx(p1),fingerprint_onnx(p2); out["primary_structural_sha256"]=a["structural_sha256"]; out["other_structural_sha256"]=b["structural_sha256"]; out["structurally_equivalent_summary"]=a["structural_sha256"]==b["structural_sha256"]
        diffs={}
        for k in ("ir","opsets","inputs","outputs","ops","domains","node_count","initializer_count"):
            if a["summary"].get(k)!=b["summary"].get(k): diffs[k]={"primary":a["summary"].get(k),"other":b["summary"].get(k)}
        out["differences"]=diffs
    else: out["note"]="Deep structural comparison currently implemented for ONNX-vs-ONNX; other formats get integrity-level comparison."
    return out

def recon_completeness(r):
    ins=r.get("inspection",{})
    completed=["Artifact identity","SHA-256","Format detection"]
    missing=[]; warnings=[]
    if ins.get("format")=="onnx":
        if ins.get("interfaces"): completed.append("Input/output interface")
        else: missing.append("Input/output interface")
        if ins.get("graph"): completed.append("Graph/operator inventory")
        else: missing.append("Graph/operator inventory")
        if ins.get("weights"): completed.append("Weight/parameter inventory")
        else: missing.append("Weight/parameter inventory")
        if ins.get("validation"): completed.append("ONNX structural validation")
        if ins.get("metadata_parse_warnings"):
            warnings.append(f"{len(ins['metadata_parse_warnings'])} metadata value(s) retained as raw strings after safe parse fallback")
    if ins.get("status")=="ERROR":
        status="PARTIAL"; missing.append("Format-specific reconnaissance")
    elif missing or ins.get("status")=="PARTIAL" or warnings:
        status="PARTIAL"
    else:
        status="COMPLETE"
    return {"status":status,"completed":completed,"missing":missing,"warnings":warnings}

def _use_color(r):
    return bool(sys.stdout.isatty() and not r.get("_no_color",False))

def _tag(level,r):
    if not _use_color(r): return f"[{level}]"
    colors={"PASS":"\033[92m","INFO":"\033[96m","WARN":"\033[93m","FAIL":"\033[91m","KEY":"\033[95m"}
    return f"{colors.get(level,'')}[{level}]\033[0m"

def print_report(r):
    section("AI/ML MODEL SECURITY RECON — KEY FINDINGS")
    print(f"{_tag('KEY',r)} Artifact : {r['artifact'].get('name')}")
    print(f"{_tag('KEY',r)} SHA-256  : {r['artifact'].get('sha256')}")
    print(f"{_tag('KEY',r)} Family   : {r['selected_model_type']}")
    print(f"{_tag('KEY',r)} Format   : {r['detected_format']}")

    rc=recon_completeness(r)
    rc_level="PASS" if rc["status"]=="COMPLETE" else "WARN"
    print(f"{_tag(rc_level,r)} Recon    : {rc['status']}")
    if rc.get("warnings"):
        for w in rc["warnings"]: print(f"  {_tag('WARN',r)} {w}")

    summary=important_summary(r)
    if summary:
        print("\nImportant model facts:")
        for k,v in summary:
            print(f"  {_tag('INFO',r)} {k:<12}: {v}")

    obs=r.get("security_observations",[])
    if obs:
        print("\nSecurity-relevant observations:")
        for x in obs:
            print(f"  {_tag(x['level'],r)} {x['message']}")

    if r.get("family_interpretation"):
        print("\nModel-family interpretation:")
        for x in r["family_interpretation"]:
            print(f"  {_tag('INFO',r)} {x}")

    ri=r.get("real_image_inference")
    if ri:
        section("REAL-IMAGE FORWARD PASS")
        if ri.get("status")!="PASS":
            print(f"{_tag('WARN',r)} {ri.get('error') or ri.get('reason')}")
        else:
            prep=ri.get("preprocessing",{})
            print(f"{_tag('PASS',r)} Inference completed in {ri.get('latency_ms')} ms")
            print(f"{_tag('INFO',r)} Image      : {prep.get('image')}")
            print(f"{_tag('INFO',r)} Preprocess : {prep.get('layout')} | {prep.get('channel_order')} | scale={prep.get('input_scale')} | {prep.get('transform')}")
            print(f"{_tag('WARN',r)} Confirm preprocessing assumptions against the reference/production pipeline.")
            for out in ri.get("interpretation",{}).get("outputs",[]):
                print(f"\n  Output[{out.get('output_index')}] shape={out.get('shape')} dtype={out.get('dtype')}")
                det=out.get("detector_interpretation")
                if det:
                    print(f"  {_tag('KEY',r)} Heuristic detector decode: {det.get('candidate_count')} candidates, {det.get('class_count')} classes")
                    print(f"  {_tag('INFO',r)} Assumption: {det.get('assumption')}")
                    print("  Top raw candidates:")
                    for c in det.get("top_candidates",[]):
                        print(f"    #{c['candidate_index']:>5}  {c['class_name']:<24} raw_score={c['raw_score']:.6f}  box={c['box_raw_4']}")
            if ri.get("raw_output_dump"):
                print(f"\n{_tag('PASS',r)} Raw outputs saved to: {ri['raw_output_dump']}")

    if r.get("deep_analysis"):
        section("DEEP MODE — HIGHLIGHTS")
        deep=r["deep_analysis"]
        fp=deep.get("structural_fingerprint",{})
        if fp:
            print(f"{_tag('KEY',r)} Structural fingerprint: {fp.get('structural_sha256') or fp.get('error')}")
        prof=deep.get("runtime_profile",{})
        if prof:
            if prof.get("status")=="COMPLETED":
                print(f"{_tag('PASS',r)} Runtime profile: {prof.get('runs')} runs | latency ms={prof.get('latency_ms')}")
                for o in prof.get("outputs",[]):
                    print(f"  {_tag('INFO',r)} output[{o.get('index')}]: min={o.get('observed_min')} max={o.get('observed_max')} NaN={o.get('nan_count')} Inf={o.get('inf_count')}")
            else:
                print(f"{_tag('WARN',r)} Runtime profile: {prof}")

    section("RECOMMENDED NEXT TESTS")
    for x in r["attack_surface"]:
        print(f"\n{_tag('KEY',r)} {x['surface']}")
        print(f"  Why: {x['why']}")
        for t in x["tests"]:
            print(f"   - {t}")

    if r.get("comparison"):
        section("MODEL COMPARISON — HIGHLIGHTS")
        c=r["comparison"]
        print(f"{_tag('INFO',r)} Byte-identical: {c.get('byte_identical')}")
        if "structurally_equivalent_summary" in c:
            level="PASS" if c.get("structurally_equivalent_summary") else "WARN"
            print(f"{_tag(level,r)} Structural summary equivalent: {c.get('structurally_equivalent_summary')}")
        if c.get("differences"):
            print(f"{_tag('WARN',r)} Structural differences: {list(c['differences'].keys())}")

    if r.get("_verbose"):
        section("VERBOSE RAW RECONNAISSANCE")
        ins=r["inspection"]
        for k in ("status","format","model_info","interfaces","graph","weights","semantic_metadata","metadata",
                  "interesting_metadata","config_summary","root_attributes","header","container","safe_load",
                  "validation","metadata_parse_warnings","version","tensor_count","metadata_count","member_count",
                  "security_sensitive_opcodes","referenced_globals","unsafe_deserialization_risk","note","warning","error","reason"):
            if k in ins: kv(k,ins[k])
        if r.get("companions",{}).get("files"):
            kv("companion_files",r["companions"]["files"])
            kv("companion_parsed",r["companions"].get("parsed"))

    section("REPORT")
    print(f"{_tag('PASS',r)} JSON report: {r['report_path']}")
    if not r.get("_verbose"):
        print(f"{_tag('INFO',r)} Use --verbose for full raw graph/weight/metadata structures.")

def main():
    p=argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description=f"""{TOOL_NAME} v{TOOL_VERSION}

Pentester-oriented reconnaissance for AI/ML artifacts.
Use --list-model-types for model families and supported formats.

Examples:

  Show supported model families and formats:
    %(prog)s --list-model-types

  Computer Vision / ONNX:
    %(prog)s yolov8.onnx --model-type computer-vision
    %(prog)s yolov8.onnx --model-type computer-vision --deep
    %(prog)s detector.onnx --model-type computer-vision --deep --profile-runs 25

  Computer Vision / real sample inference:
    %(prog)s best.onnx --model-type computer-vision --input-image stop.jpg --top-k 10
    %(prog)s best.onnx --model-type computer-vision --input-image stop.jpg --dump-raw-output raw_outputs.npz

  Language / LLM:
    %(prog)s llama-model.gguf --model-type language-llm
    %(prog)s model.safetensors --model-type language-llm

  Multimodal:
    %(prog)s vision_language_model.safetensors --model-type multimodal

  Audio / Speech:
    %(prog)s whisper.onnx --model-type audio-speech

  Time-Series / Sequential:
    %(prog)s anomaly_detector.onnx --model-type time-series

  Tabular / Classical ML:
    %(prog)s model.pkl --model-type tabular-classical
    %(prog)s xgboost_model.json --model-type tabular-classical
    %(prog)s lightgbm_model.txt --model-type tabular-classical

  Generative:
    %(prog)s diffusion_model.safetensors --model-type generative

  Reinforcement Learning:
    %(prog)s policy.zip --model-type reinforcement-learning

  Graph Neural Network:
    %(prog)s gnn_model.pt --model-type graph

  Recommendation / Ranking:
    %(prog)s ranking_model.onnx --model-type recommendation-ranking

  Automatic / Generic mode:
    %(prog)s unknown_model.onnx --model-type auto

  Compare approved vs deployed ONNX model:
    %(prog)s approved.onnx --model-type computer-vision --deep --compare deployed.onnx

  Save JSON report to a custom path:
    %(prog)s model.onnx --model-type computer-vision --deep --json reports/model_recon.json
""")
    p.add_argument("model",nargs="?",help="model artifact or TensorFlow SavedModel directory")
    p.add_argument("--model-type",choices=sorted(MODEL_TYPES),help="model family; if omitted in an interactive terminal a selector is shown")
    p.add_argument("--list-model-types",action="store_true",help="show supported model families, example use cases and artifact formats")
    p.add_argument("--deep",action="store_true",help="run deeper safe analysis where supported; includes ONNX structural fingerprinting and runtime profiling")
    p.add_argument("--profile-runs",type=int,default=5,help="number of synthetic ONNX inference runs used by --deep (default: 5)")
    p.add_argument("--compare",metavar="OTHER_MODEL",help="compare with another artifact; ONNX-to-ONNX supports structural comparison")
    p.add_argument("--json",dest="json_path",help="write the JSON report to a custom path; default: <artifact>.security-recon.json")
    p.add_argument("--input-image",metavar="IMAGE",help="ONNX computer-vision: run a real image through the model and inspect raw outputs")
    p.add_argument("--top-k",type=int,default=10,help="number of top detector candidates to display for --input-image (default: 10)")
    p.add_argument("--dump-raw-output",metavar="NPZ",help="save raw outputs from --input-image to a compressed .npz file")
    p.add_argument("--resize-mode",choices=["auto","stretch","letterbox"],default="auto",help="image resize mode for --input-image (default: auto)")
    p.add_argument("--channel-order",choices=["rgb","bgr"],default="rgb",help="image channel order for --input-image (default: rgb)")
    p.add_argument("--input-scale",choices=["auto","0-1","0-255"],default="auto",help="numeric input scaling for --input-image (default: auto)")
    p.add_argument("--verbose",action="store_true",help="print detailed raw reconnaissance structures; default console output is concise")
    p.add_argument("--no-color",action="store_true",help="disable ANSI highlighting in console output")
    a=p.parse_args()
    if a.list_model_types: list_types(); return 0
    if not a.model: p.error("model is required unless --list-model-types is used")
    path=Path(a.model).expanduser().resolve()
    if not path.exists(): print("ERROR: not found:",path,file=sys.stderr); return 2
    model_type=a.model_type or (choose_type() if sys.stdin.isatty() else "auto")
    fmt=detect_format(path); r={"tool":{"name":TOOL_NAME,"version":TOOL_VERSION,"python":sys.version.split()[0],"platform":platform.platform()},"artifact":identity(path),"selected_model_type":model_type,"detected_format":fmt}
    if not supported(model_type,path): r["format_warning"]=f"{path.suffix or 'directory'} is not a primary listed format for {model_type}; format/generic recon will still be attempted."
    try: r["inspection"]=inspect_artifact(path,fmt)
    except Exception as e: r["inspection"]={"format":fmt,"status":"ERROR","error":str(e)}
    files=companion_files(path,model_type); r["companions"]=parse_companions(files); r["family_interpretation"]=family_hints(r["inspection"],model_type); r["attack_surface"]=attack_surface(r["inspection"],model_type)
    if a.input_image:
        if fmt=="onnx" and model_type in ("computer-vision","auto"):
            r["real_image_inference"]=run_real_image_inference(
                path,a.input_image,r["inspection"],top_k=max(1,a.top_k),
                resize_mode=a.resize_mode,channel_order=a.channel_order,
                input_scale=a.input_scale,dump_raw_output=a.dump_raw_output
            )
        else:
            r["real_image_inference"]={"status":"SKIPPED","reason":"--input-image currently supports ONNX computer-vision/auto targets."}
    r["security_observations"]=security_observations(r)
    if a.deep:
        deep={}
        if fmt=="onnx":
            try: deep["structural_fingerprint"]=fingerprint_onnx(path)
            except Exception as e: deep["structural_fingerprint"]={"status":"FAIL","error":str(e)}
            deep["runtime_profile"]=profile_onnx(path,max(1,a.profile_runs))
        else: deep["note"]="Deep structural/runtime mode is currently richest for ONNX; safe format-specific metadata is still reported."
        r["deep_analysis"]=deep
    if a.compare:
        other=Path(a.compare).expanduser().resolve(); r["comparison"]=compare(path,other) if other.exists() else {"status":"ERROR","error":f"not found: {other}"}
    r["recon_completeness"]=recon_completeness(r)
    r["_verbose"]=bool(a.verbose)
    r["_no_color"]=bool(a.no_color)
    out=Path(a.json_path).expanduser().resolve() if a.json_path else path.parent/f"{path.name}.security-recon.json"; r["report_path"]=str(out); out.write_text(json.dumps(safe(r),indent=2,ensure_ascii=False),encoding="utf-8"); print_report(r); return 0
if __name__=="__main__": raise SystemExit(main())
