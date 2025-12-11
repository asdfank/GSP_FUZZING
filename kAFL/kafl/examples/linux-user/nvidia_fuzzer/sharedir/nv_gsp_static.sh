#!/usr/bin/env bash
# 收敛 nvidia.ko 中与 GSP/RPC/固件相关的代码区间（静态方法，无需 BPF）
# 产物：
#   - nv_gsp_ranges.txt  : 绝对地址区间 [start-end)
#   - nv_gsp_ranges.rel  : 相对 .text 的偏移区间 [+0x... - +0x...]

set -euo pipefail
export LC_ALL=C

# ===== 可按需自定义 =====
# 关键词（区分度优先，默认覆盖 gsp / rpc / firmware / mailbox / doorbell / falcon / ucode / nvfw / fmc）
KEYWORDS_REGEX="${KEYWORDS_REGEX:-(gsp|rpc|firmware|mailbox|doorbell|falcon|ucode|nvfw|fmc)}"
# 区间扩展与合并参数（越小越“紧”）
EXPAND_BEFORE_HEX="${EXPAND_BEFORE_HEX:-0x200}"
EXPAND_AFTER_HEX="${EXPAND_AFTER_HEX:-0x400}"
MERGE_GAP_HEX="${MERGE_GAP_HEX:-0x200}"
# 目标模块（可改成具体路径；默认自动找 nvidia.ko）
KO="${1:-$(modinfo -n nvidia)}"
# =======================

[[ -r "$KO" ]] || { echo "ERR: cannot read KO=$KO" >&2; exit 1; }

TEXT_BASE="$(cat /sys/module/nvidia/sections/.text)"
RO_BASE="$(cat /sys/module/nvidia/sections/.rodata)"

echo "[*] nvidia.ko: $KO"
echo "[*] .text  @ $TEXT_BASE"
echo "[*] .rodata@ $RO_BASE"
echo "[*] KEYWORDS_REGEX = $KEYWORDS_REGEX"
echo "[*] EXPAND_BEFORE=$EXPAND_BEFORE_HEX  EXPAND_AFTER=$EXPAND_AFTER_HEX  MERGE_GAP=$MERGE_GAP_HEX"

# 计算 .text 结束地址（用于夹紧锚点）
TEXT_SIZE_HEX="$(objdump -h "$KO" | awk '$2==".text"{print "0x"$3; found=1} END{if(!found) exit 1}')"
export TEXT_BASE_HEX="$TEXT_BASE"
export TEXT_SIZE_HEX="$TEXT_SIZE_HEX"

python3 - <<'PY'
import os
ts = int(os.environ["TEXT_BASE_HEX"], 16)
te = ts + int(os.environ["TEXT_SIZE_HEX"], 16)
print(f"[*] .text range: 0x{ts:x} - 0x{te:x} (size={os.environ['TEXT_SIZE_HEX']})")
PY


# === 1) 构建 rodata* 段的“运行时基址”映射表（把所有 rodata* 按 readelf 顺序拼成一段） ===
# 记录每个 rodata 子段的：name  file_off  size  runtime_base(=RO_BASE+累计)
mapfile -t RSEC < <(readelf -WS "$KO" | awk 'BEGIN{IGNORECASE=1} $2 ~ /^\.rodata/ {printf "%s 0x%s 0x%s\n",$2,$5,$6}')
(( ${#RSEC[@]} )) || { echo "ERR: no .rodata* sections found in $KO" >&2; exit 1; }

CUMU=0
> /tmp/ro_map.tsv
for line in "${RSEC[@]}"; do
  set -- $line; sec=$1; offhex=$2; sizehex=$3
  OFF=$((offhex)); SIZ=$((sizehex))
  (( SIZ > 0 )) || continue
  RUNTIME_BASE=$((RO_BASE + CUMU))
  printf "%s\t0x%X\t0x%X\t0x%X\n" "$sec" "$OFF" "$SIZ" "$RUNTIME_BASE" >> /tmp/ro_map.tsv
  CUMU=$((CUMU + SIZ))
done
echo "[*] rodata stitched size: $(printf "0x%X\n" "$CUMU")"

# === 2) 提取“关键词字符串”的运行时绝对地址集合 ===
> /tmp/gsp_str_addrs.txt
while IFS=$'\t' read -r SEC_NAME SEC_OFF_HEX SEC_SIZ_HEX SEC_RBASE_HEX; do
  OFF=$((SEC_OFF_HEX)); SIZ=$((SEC_SIZ_HEX)); RBASE=$((SEC_RBASE_HEX))
  TMP="/tmp/ro_${SEC_NAME//./_}.bin"
  dd if="$KO" of="$TMP" bs=1 skip="$OFF" count="$SIZ" status=none 2>/dev/null || true

  # strings -tx 输出：<hex_off> <string...>
  strings -a -tx "$TMP" \
  | awk -v base="$RBASE" -v re="$KEYWORDS_REGEX" '
      BEGIN{IGNORECASE=1}
      $2 ~ re {
        off=strtonum("0x"$1);
        printf("0x%016x\n", base+off);
      }' >> /tmp/gsp_str_addrs.txt
done < /tmp/ro_map.tsv

sort -u /tmp/gsp_str_addrs.txt -o /tmp/gsp_str_addrs.txt
KW_CNT=$(wc -l < /tmp/gsp_str_addrs.txt)
echo "[*] keyword string addrs: $KW_CNT"
(( KW_CNT > 0 )) || { echo "WARN: no keyword strings matched. Try loosening KEYWORDS_REGEX." >&2; }

# === 3) 用 objdump -dr 拿到“每条指令的 .rodata 重定位目标的运行时绝对地址” ===
OBJ_RELOC="/tmp/nv_text_reloc.S"
objdump -dr -M intel --adjust-vma="$TEXT_BASE" "$KO" > "$OBJ_RELOC"

# 生成映射：上一条指令地址  目标 rodata 绝对地址（按子段基址累加）
#   relocation 行示例：
#     R_X86_64_32S  .rodata.str1.1+0x1234
#   需要：用 ro_map.tsv 里该子段的 runtime_base + 0x1234
awk -v MAP="/tmp/ro_map.tsv" '
  BEGIN{
    IGNORECASE=1;
    # 加载 rodata 段名 -> runtime_base 映射
    while ((getline < MAP) > 0) {
      split($0, a, "\t"); sec=a[1]; rbase=a[4];
      rb[sec]=strtonum(rbase);
    }
  }
  /^[0-9a-f]+:/ { last=$0; next }    # 记录上一条指令（行首是地址）
  /R_X86_64_/ && /\.rodata/ {
    if (match(last,/^([0-9a-f]+):/,m1) &&
        match($0, /(\.rodata(\.[^+[:space:]]*)?)\+0x([0-9a-f]+)/,m2)) {
      ins="0x" m1[1];
      sec=m2[1]; off="0x" m2[3];
      if (sec in rb) {
        tgt = rb[sec] + strtonum(off);
        printf("%s %016x\n", ins, tgt);
      }
    }
  }' "$OBJ_RELOC" > /tmp/ins_ro_targets.txt

echo "[*] reloc pairs (ins → ro_abs): $(wc -l < /tmp/ins_ro_targets.txt)"


# === 4) 只保留“目标 rodata 所在页 ∈ 关键词字符串所在页集合（可±N页）”的锚点 ===
: "${PWIN:=0}"         # 页窗口：0=同页；1=±1页……
PAGE_SHIFT=12          # 4KB

python3 - <<'PY'
import os
PWIN = int(os.environ.get("PWIN","0"))
PAGE_SHIFT = 12
PAGE_SIZE  = 1 << PAGE_SHIFT

# 关键词字符串地址 -> 页集合
kw_pages = set()
with open("/tmp/gsp_str_addrs.txt") as f:
    for ln in f:
        s = ln.strip()
        if s:
            kw_pages.add(int(s, 16) // PAGE_SIZE)

# reloc 目标：/tmp/ins_ro_targets.txt 形如 "<ins> <tgt_abs_hex>"
anchors = set()
with open("/tmp/ins_ro_targets.txt") as f:
    for ln in f:
        s = ln.strip()
        if not s: continue
        ins, tgt_hex = s.split()
        tgt_pg = int(tgt_hex, 16) // PAGE_SIZE
        # 同页或 ±PWIN 页
        if any((tgt_pg + d) in kw_pages for d in range(-PWIN, PWIN+1)):
            anchors.add(ins)

with open("/tmp/nv_anchor_addrs.txt","w") as out:
    out.write("\n".join(sorted(anchors)))
print(f"[*] filtered anchors (page-match, PWIN={PWIN}): {len(anchors)}")
PY

# === 5) 夹紧到 .text 范围（避免负偏移/越界） ===
python3 - <<'PY'
import os
# 直接用 16 进制字符串计算 ts / te，避免 bash 十进制溢出
ts = int(os.environ["TEXT_BASE_HEX"], 16)
te = ts + int(os.environ["TEXT_SIZE_HEX"], 16)
good = []
with open("/tmp/nv_anchor_addrs.txt") as f:
    for ln in f:
        s = ln.strip()
        if not s: continue
        try:
            a = int(s, 16)   # anchors 文件里是 0x... 形式
        except ValueError:
            continue
        if ts <= a < te:
            good.append(s)
open("/tmp/nv_anchor_addrs.txt","w").write("\n".join(good))
print(f"[*] anchors after clamp: {len(good)}")
PY


# === 6) 扩窗合并 → 生成绝对区间 ===
python3 - "$EXPAND_BEFORE_HEX" "$EXPAND_AFTER_HEX" "$MERGE_GAP_HEX" << 'PY' > nv_gsp_ranges.txt
import sys
exp_b=int(sys.argv[1],16); exp_a=int(sys.argv[2],16); gap=int(sys.argv[3],16)
pts=[int(x.strip(),16) for x in open("/tmp/nv_anchor_addrs.txt") if x.strip()]
if not pts:
    # 没有锚点就输出空文件并退出，避免 IndexError
    open("nv_gsp_ranges.txt","w").close()
    sys.exit(0)
pts=sorted(set(pts))
ranges=[(max(0,a-exp_b), a+exp_a) for a in pts]
ranges.sort()
out=[]; s,e=ranges[0]
for x,y in ranges[1:]:
    if x<=e+gap: e=max(e,y)
    else: out.append((s,e)); s,e=x,y
out.append((s,e))
for i,(a,b) in enumerate(out,1):
    print(f"{i:02d} 0x{a:016x}-0x{b:016x}")
PY

echo "[*] wrote nv_gsp_ranges.txt"; head -n 20 nv_gsp_ranges.txt || true

# === 7) 相对 .text 偏移版（便于跨机/跨重启复用） ===
python3 - << 'PY' > nv_gsp_ranges.rel
import os
base = int(os.environ["TEXT_BASE_HEX"], 16)
for ln in open("nv_gsp_ranges.txt"):
    ln=ln.strip()
    if not ln: continue
    a,b=ln.split()[1].split('-')
    a=int(a,16); b=int(b,16)
    print(f"+0x{a-base:x}-+0x{b-base:x}")
PY


echo "[*] wrote nv_gsp_ranges.rel"; head -n 20 nv_gsp_ranges.rel || true

