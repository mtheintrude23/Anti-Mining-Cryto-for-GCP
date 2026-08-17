# Cau hinh IAM toi thieu cho gcp_delete_self / gcp_shutdown_self

Muc tieu: moi VM chi duoc phep goi `instances.delete` / `instances.stop` / `instances.get`
tren **chinh no**, khong duoc dung cho VM khac trong cung project. Thuc hien 1 lan cho
project (buoc 1-2), roi lap lai buoc 3-5 cho tung instance.

## 1. Tao custom role toi thieu (1 lan / project)

```bash
PROJECT_ID="ten-project-cua-ban"

gcloud iam roles create antiCryptoMinerdSelfManage \
  --project="$PROJECT_ID" \
  --title="Anti-CryptoMinerd Self Manage" \
  --description="Cho phep 1 VM dung/xoa chinh no khi phat hien dao coin" \
  --permissions=compute.instances.get,compute.instances.stop,compute.instances.delete \
  --stage=GA
```

Chi 3 quyen nay — khong co `compute.instances.list`, khong co quyen tren disk/network/firewall.
Khong dung role dung san nhu `roles/compute.instanceAdmin` hay `roles/editor` (qua rong).

## 2. Tao service account rieng cho agent (1 lan / project, hoac 1 / VM neu muon co lap hon)

```bash
gcloud iam service-accounts create acm-agent \
  --project="$PROJECT_ID" \
  --display-name="AntiCryptoMinerd agent"
```

## 3. Gan role, gioi han bang IAM Condition theo dung ten instance

Day la buoc quan trong nhat: dieu kien CEL duoi day khien quyen xoa/dung **chi co hieu luc
voi 1 instance duy nhat**, du service account duoc dung chung cho nhieu VM.

```bash
INSTANCE_NAME="ten-vm-can-bao-ve"
ZONE="asia-southeast1-a"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:acm-agent@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="projects/${PROJECT_ID}/roles/antiCryptoMinerdSelfManage" \
  --condition="expression=resource.name.endsWith('/instances/${INSTANCE_NAME}'),title=self-only-${INSTANCE_NAME}"
```

Neu ban co nhieu VM dung chung 1 service account, chay lai lenh tren cho tung
`INSTANCE_NAME` — moi lenh them 1 dieu kien rieng, VM A khong the xoa VM B du
cung service account.

## 4. Gan service account vao VM

- **VM moi tao:**
  ```bash
  gcloud compute instances create "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --service-account="acm-agent@${PROJECT_ID}.iam.gserviceaccount.com" \
    --scopes="https://www.googleapis.com/auth/cloud-platform" \
    ... (cac tham so khac)
  ```
- **VM co san** (yeu cau dung may trong luc doi service account):
  ```bash
  gcloud compute instances stop "$INSTANCE_NAME" --zone="$ZONE"
  gcloud compute instances set-service-account "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --service-account="acm-agent@${PROJECT_ID}.iam.gserviceaccount.com" \
    --scopes="https://www.googleapis.com/auth/cloud-platform"
  gcloud compute instances start "$INSTANCE_NAME" --zone="$ZONE"
  ```

`--scopes=cloud-platform` la bat buoc: GCE legacy scopes (vd `compute-rw`) khong du de IAM
Condition o buoc 3 phat huy tac dung dung muc — phai dung cloud-platform scope + IAM role/condition
de kiem soat quyen thuc su.

## 5. Kiem tra

```bash
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:acm-agent@${PROJECT_ID}.iam.gserviceaccount.com" \
  --format="table(bindings.role,bindings.condition.title)"
```

Phai thay dung 1 role `antiCryptoMinerdSelfManage` voi dieu kien dung ten VM tuong ung.
Neu thay them role khac (Editor, Owner, compute admin...) tu truoc — go bo di, vi no vo hieu
hoa toan bo gioi han o buoc 3.

## 6. Nhieu instance (50+): dung script tu dong

Lam tay tung lenh cho 50 VM la khong thuc te. Dung `docs/bulk-iam-setup.sh`:

```bash
cd docs
cp instances.csv.example instances.csv
notepad instances.csv   # hoac nano/vim — dien dung instance_name,zone cho tung VM, 1 dong/VM

chmod +x bulk-iam-setup.sh
./bulk-iam-setup.sh my-project-id
```

Script tu dong: tao role (neu chua co) -> tao service account (neu chua co) -> voi moi dong
trong `instances.csv`: gan IAM Condition rieng cho instance do, roi STOP -> gan service account
-> START lai VM (bat buoc phai dung VM de doi service account, khong co cach nao lam luc dang
chay). Chay lai script nhieu lan la an toan (idempotent) — VM da cau hinh dung se khong bi
dung lai lan nua vi script kiem tra status truoc.

**Luu y khi chay tren 50 VM:** moi VM se bi dung vai chuc giay-vai phut trong luc doi service
account. Neu day la production dang phuc vu traffic, nen chay theo batch nho (vd 5-10 VM/lan,
sua vong lap trong script hoac chia nho `instances.csv`) thay vi dung ca 50 cung luc.

## 7. config.json tren tung VM

```json
"gcp_delete_self": true,
"gcp_project_id": "",
"gcp_zone": "",
"gcp_instance_name": "",
"dry_run": false
```

De trong `gcp_project_id`/`gcp_zone`/`gcp_instance_name` la an toan nhat: service se tu doc
tu GCE metadata cua chinh no, khong the bi go nham ten VM khac vao config roi vo tinh xoa
sai may.
