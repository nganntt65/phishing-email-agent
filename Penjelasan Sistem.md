PENJELASAN SISTEM CAMPUSGUARD AI
Untuk tim sendiri, dalam bahasa Indonesia sederhana. Diperbarui 13 November 2026.
============================================================================================

Isi:
   1. Apa itu CampusGuard AI
   2. Alur kerja dari input sampai hasil
   3. Pondasi: mesin aturan (rule-based)
   4. Tab Scan
   5. Tab Analyst
   6. Tab Evaluation dan angka saat ini
   7. Lapisan AI (Gemini): apa yang berubah saat dinyalakan
   8. Memori kampanye dan privasi
   9. Batasan yang harus diakui
  10. Pertanyaan yang mungkin ditanyakan juri

Semua angka akurasi berasal dari data sintetis (buatan sendiri), bukan dari phishing nyata.


1. APA ITU CAMPUSGUARD AI
--------------------------------------------------------------------------------------------

Nama      CampusGuard AI
Tagline   AI-Powered Email Security for Students
Masalah   Mahasiswa sering menerima email palsu yang menyamar sebagai kampus: reset password,
          beasiswa, tagihan, kuota mailbox. Satu klik di link palsu bisa membuat akun kampus
          diambil alih.

Mahasiswa memasukkan link, PDF email, atau file .eml. Aplikasi menjawab tiga hal: seberapa
berbahaya, kenapa (dengan kutipan dari email), dan apa yang harus dilakukan sekarang.

Satu kalimat untuk juri:
  "CampusGuard AI adalah sistem agentic. Mesin aturan memeriksa fakta teknis (siapa pengirim,
  ke mana link, naskah scam apa yang dipakai), lalu model AI Gemini membaca isi pesan dan
  menjelaskan alasannya. Tanpa AI, sistem tetap berjalan dengan aturan dan memberi tahu
  pengguna."

Tiga tab:
  Scan        untuk mahasiswa, hasil dalam bahasa sederhana
  Analyst     untuk orang teknis, setiap langkah agen tampil satu per satu
  Evaluation  mengukur seberapa sering aplikasi benar pada dataset berlabel


2. ALUR KERJA DARI INPUT SAMPAI HASIL
--------------------------------------------------------------------------------------------

Inilah arti "agentic" di sini: sebuah orchestrator menjalankan beberapa alat (tool) secara
berurutan, lalu menggabungkan hasilnya menjadi satu keputusan. Untuk email dan PDF:

  1. Pembersihan input (sanitizer)
     HTML dibuang, link dan lampiran dikumpulkan, teks yang disembunyikan dengan CSS dicatat,
     alamat pengirim dan penerima dibaca.

  2. Memuat panduan agen
     Prompt dasar dan dua playbook berbentuk file .md (content-analysis.md dan
     scam-scoring.md). Mesin aturan di kode mengikuti playbook yang sama, jadi Gemini dan
     aturan memakai rubrik yang identik.

  3. Pemeriksa pengirim (tool 1)
     Siapa pengirimnya dan bisakah dibuktikan? Lihat bagian 3B.

  4. Pemindai link dan lampiran (tool 2)
     Ke mana link-nya pergi, dan apakah domainnya tiruan? Lihat bagian 3C.

  5. Memori kampanye (tool 3)
     Apakah pola serangan ini pernah terlihat? Lihat bagian 8.

  6. Naskah scam (tool 4)
     Apakah kata-katanya cocok dengan naskah scam yang sudah dikenal? Lihat bagian 3D.

  7. Pembaca isi pesan
     Gemini (kalau ada API key) atau aturan kata kunci (kalau tidak ada) menilai bagian
     kata-kata. Lihat bagian 3E dan 7.

  8. Skor akhir, level, kartu hasil
     Empat komponen dijumlahkan, skor minimum diterapkan, level ditentukan, kartu hasil
     disusun. Kalau HIGH atau CRITICAL, pola serangannya disimpan ke memori kampanye.

Link yang ditempel sendiri memakai jalur pendek: pemindai link, lalu kartu hasil.


3. PONDASI: MESIN ATURAN (RULE-BASED)
--------------------------------------------------------------------------------------------

Mesin aturan adalah pondasi sistem. Ia selalu berjalan, dengan atau tanpa AI, dan semua
angkanya terbuka. Tanpa API key, inilah seluruh sistem.

3A. RUMUS SKOR

  Skor akhir 0 sampai 100 = jumlah empat komponen, lalu skor minimum (floor), lalu dipotong
  di 100.

    Komponen            Maksimum   Pertanyaan yang dijawab
    ------------------  ---------  ---------------------------------------------
    Pengirim                  35   Siapa pengirimnya, dan bisakah dibuktikan?
    Link dan lampiran         30   Ke mana link-nya pergi?
    Kata-kata                 35   Apa yang diminta email ini, dan dengan cara apa?
    Memori kampanye           15   Pernahkah pola ini terlihat?

  Skor minimum (diterapkan setelah penjumlahan):
    Naskah scam dikenal dan pengirim/link tidak terverifikasi      minimal 60
    Lampiran executable (.exe, .scr, .js, dan sejenisnya)          minimal 85
    Percobaan prompt injection                                     minimal 88

  Level dan label yang dilihat mahasiswa:
    85 - 100    CRITICAL   Likely scam
    60 - 84     HIGH       Suspicious email
    30 - 59     MEDIUM     Unverified sender
    0 - 29      LOW        No red flags found, atau "Low risk" bila ada tanda kecil

  Skor 60 ke atas dihitung sebagai phishing di tab Evaluation.
  Batas 60 itu bisa diubah lewat PHISHING_THRESHOLD di .env.

3B. KOMPONEN PENGIRIM (MAKS 35)

  Tiga pertanyaan dipisahkan:

  Terautentikasi?   DMARC lulus, atau SPF dan DKIM keduanya lulus. Artinya domain itu
                    benar-benar yang mengirim. Hanya ada di file .eml. PDF dan teks tempelan
                    tidak membawa header, statusnya "unavailable" dan tidak dihukum.

  Siapa domain itu? Daftar trusted (155 domain: 151 universitas asli termasuk ntpu.edu.tw,
                    ditambah login Microsoft 365, microsoft.com, accounts.google.com,
                    github.com). Atau domain universitas asli (.edu, .ac.id, .edu.tw, dan
                    lain-lain; akhiran ini tidak bisa didaftarkan sembarang orang). Atau
                    webmail gratis (gmail, yahoo, outlook): siapa pun bisa membuatnya, jadi
                    lulus DMARC hanya membuktikan "dikirim lewat Gmail", bukan siapa
                    penulisnya. Atau domain yang tidak dikenal.

                    Daftar trusted bisa diubah lewat tombol "Trusted domains" di tab Analyst.
                    PayPal, Stripe, dan google.com sengaja tidak masuk (docs.google.com sering
                    dipakai form phishing), jadi link PayPal asli berlabel Unverified: aman,
                    hanya belum terverifikasi. Daftar disimpan di memori; kalau REDIS_URL
                    diisi dan Redis itu sudah punya daftar lama, daftar lama yang dipakai.

  Terverifikasi?    Terautentikasi DAN (ada di daftar trusted ATAU domain universitas asli
                    yang bukan tiruan). Hanya pengirim terverifikasi yang bebas dari skor
                    minimum naskah scam.

  Poin:
    Domain tiruan                                                  +20
      Lima jenis: tiruan merek (paypa1-support.com), berdandan seperti alamat kampus
      (westbrook-edu.com, ntpu.edu.tw-login.com), angka pengganti huruf di nama kampus
      (westbr0ok.edu, harr0wgate.ac.uk), tiruan domain di daftar trusted (ntpu-login.com,
      ntpu.edu.tvv, harvrad.edu, ntpuedu.tw), dan domain yang membawa nama universitas si penerima di
      luar domain aslinya (harrowgate-it.help dikirim ke @harrowgate.ac.uk). Yang terakhir
      memakai alamat penerima, jadi tidak perlu konfigurasi kampus.
    DMARC gagal, atau "none" pada domain tiruan/trusted                +15
      (+8 bila hanya "none" pada domain tidak dikenal)
    Domain trusted tetapi autentikasi gagal (header dipalsukan)        +15
    SPF gagal                                                          +8
    DKIM gagal                                                         +7
    Domain pengirim disusun dari kata-kata keamanan                    +10 (+5 bila satu kata)
      Contoh: webmail-upgrade-center.com, exec-mailbox.org, fastmail-secure.net.
    Nama tampilan mengaku jabatan atau merek                           +12 (+8 di PDF)
      "Prof.", "Dr.", "Dean", "CFO", "IT Support", "Accounts", "Team", "Office" dari alamat
      webmail gratis, atau dari domain tidak dikenal yang tidak terautentikasi. Tidak pernah
      untuk pengirim trusted atau universitas asli: "Dr. Sutanto" dari westbrook.edu adalah
      dosen biasa.
    Reply-To berbeda domain dengan pengirim                            +12
    Return-Path berbeda domain dengan pengirim                         +5

  Pengirim terverifikasi tanpa Reply-To aneh: komponen ini 0.

3C. KOMPONEN LINK DAN LAMPIRAN (MAKS 30)

  Dipakai nilai TERTINGGI di antara semua link, lalu ditambah dua hal di bawahnya.

    Domain tiruan (lima jenis yang sama dengan 3B)                     30
    Terdaftar di Google Safe Browsing (butuh key terpisah)             30
    Path login pada TLD berisiko                                       30
    IP mentah sebagai alamat (http://45.83.164.69/login)               28
    Link pendek (bit.ly, tinyurl, t.co, dan lain-lain)                 22
      Menyembunyikan tujuan sebenarnya. Aplikasi tidak mengikuti redirect.
    Domain disusun dari kata-kata keamanan                             22 (12 bila satu kata)
      drive-docs-shared.com, wallet-verify-center.com, secure-docs-share.net.
    Nama universitas terdaftar dengan akhiran lain, plus tanda login   30
      ntpu.com/login, sso.ntpu.com, sso.ntpu.tw. Siapa pun bisa membeli alamat ini.
      Tanpa tanda login (ntpu.net, columbia.com) hanya 12 dan berlabel Unverified, karena
      nama yang sama bisa milik perusahaan asli (columbia.com adalah merek pakaian).
      Hanya untuk nama 4 huruf atau lebih (ui.com adalah perusahaan Ubiquiti).
    Punycode (huruf dari abjad lain yang mirip)                        20
    TLD yang sering disalahgunakan (.xyz, .top, .click, ...)           18
    Path login pada domain yang tidak dikenal                          18
    HTTP tanpa enkripsi                                                10

  Tambahan:
    Tulisan link tidak cocok dengan tujuannya                          +15
    Lampiran yang bisa dijalankan                                      +25

  Link pihak pertama (first-party):
    Link ke domain pengirim sendiri, bila pengirim terautentikasi (atau headernya memang
    tidak ada, seperti PDF) dan bukan domain tiruan atau domain kata-kata keamanan. Untuk
    link seperti ini, dua tanda lemah (path login, http) tidak dihitung. Contoh:
    portal.westbrook.edu/password/reset dari no-reply@westbrook.edu bukan umpan.
    Alasannya: memalsukan baris From hanya berguna bagi penyerang kalau link-nya pergi ke
    tempat lain.

  Link ke domain trusted tidak menambah skor.

  Skor untuk link yang ditempel sendiri (tanpa email) dihitung lain: poin tertinggi di tabel
  di atas dikali 3, maksimal 100. Jadi domain tiruan (30) tampil 90, domain kata-kata keamanan
  (22) tampil 66, satu kata keamanan (12) tampil 36, path login di domain tidak dikenal (18)
  tampil 54. Trik "@" minimal 75, salah ketik halaman login di domain asli tetap 40, dan
  domain trusted 0. Label "Suspicious link" tidak pernah di bawah 60.

3D. NASKAH SCAM DIKENAL (SKOR MINIMUM 60)

  Komponen di atas dijumlahkan, jadi scam yang hanya mengandalkan kalimat tidak akan pernah
  sampai 60. Delapan naskah ini dikenal tim keamanan sebagai scam begitu terlihat. Kalau
  cocok DAN konteksnya tidak bisa menjamin email itu, skor akhir minimal 60.

    Naskah                       Yang dicocokkan                      Minimum berlaku bila
    ---------------------------  -----------------------------------  ---------------------------
    Permintaan gift card         beli gift card, kirim kode/foto      pengirim tidak terverifikasi
    Biaya untuk mencairkan uang  "processing fee", "fee to release",  pengirim tidak terverifikasi
                                 dengan konteks hadiah/beasiswa/
                                 refund
    Ganti rekening bank          "we changed our bank/ACH details",   pengirim tidak terverifikasi
                                 "new routing number"                 atau Reply-To ke tempat lain
    Transfer uang mendesak/      wire/transfer/send money + mendesak  pengirim tidak terverifikasi,
    rahasia                      atau rahasia ("keep this between     nama tampilan menyamar, atau
                                 us", "do not call")                  Reply-To ke tempat lain
    Minta data identitas/bank    isi formulir dengan student ID,      pengirim tidak terverifikasi
                                 direct deposit, kartu, paspor        dan ada data perbankan
    Pembuka "Are you available?" dua atau lebih dari: tanya ada/      tidak ada link, pengirim
                                 tidak, minta tolong tanpa jelas,     tidak terverifikasi
                                 minta balas cepat atau pindah ke
                                 WhatsApp/LINE, "sedang rapat, jangan
                                 telepon"
    Umpan kredensial             minta sign in/verify/reset/unlock,   ada link yang bukan trusted,
                                 ancaman akun ditangguhkan, atau      bukan first-party, bukan
                                 "mailbox penuh"                      domain universitas; atau
                                                                      pengirim tiruan; atau link
                                                                      tidak terbaca (PDF) dan
                                                                      pengirim bukan universitas/
                                                                      trusted
    Pemberitahuan paket gagal    "could not be delivered",            link pendek atau mencurigakan,
                                 "reschedule delivery"                pengirim tidak terverifikasi

  Setiap naskah juga menambah poin ke komponen kata-kata (lihat 3E) dan mengutip kalimat
  yang cocok sebagai bukti. Skor minimum tampil di hasil sebagai "Known scam script".

  Kenapa aman dari alarm palsu: pengirim terverifikasi (universitas asli atau daftar trusted,
  lulus autentikasi) yang link-nya hanya ke domain sendiri atau trusted tidak pernah kena
  skor minimum. Reset password asli dari no-reply@westbrook.edu tetap LOW. Domain trusted
  yang gagal autentikasi (header dipalsukan) TIDAK terverifikasi, jadi tetap kena.

3E. KOMPONEN KATA-KATA, MODE ATURAN (MAKS 35)

    Urgensi (tekanan waktu)                       7, atau 11 bila dua kata kunci atau lebih
    Ancaman dan konsekuensi buruk                 6, atau 9 bila dua kata kunci atau lebih
    Menyamar merek atau otoritas                  8
    Pola BEC (CEO, gift card, payroll)            6 (bila tidak menyamar merek)
    Salam generik atau link yang menipu           4
    Percobaan prompt injection                    5
    Meminta uang                                  8
    Meminta login atau verifikasi akun            4 (bila tidak meminta uang)
    Naskah scam (3D): gift card 12, biaya cair 12, ganti rekening 10, transfer 12, data
    identitas 10 (6 tanpa data bank), pembuka BEC 10 (4 bila satu tanda), umpan kredensial
    10 + 8 ancaman + 8 mailbox penuh, paket gagal 8

  Jumlahnya dipotong di 35.

  Batas jinak (benign cap): pengirim terverifikasi, tanpa Reply-To aneh, semua link trusted
  atau first-party, tanpa link mencurigakan dan tanpa lampiran berbahaya: komponen kata-kata
  dibatasi 4 dan tidak ada skor minimum. Pengingat tugas dari dosen yang berkata "submit
  immediately" tetap LOW.

  Kata kunci aturan hanya bahasa Inggris. Email berbahasa Mandarin atau Indonesia dinilai
  dari pengirim dan link-nya saja (keduanya tidak bergantung pada bahasa), kecuali Gemini
  dinyalakan.

3F. MEMORI KAMPANYE (MAKS 15)

  +15 bila pola serangan yang sama pernah dinilai HIGH atau CRITICAL. Lihat bagian 8.

3G. CONTOH PERHITUNGAN

  Gift card dari "Prof. Omar Sutanto" <prof.sutanto5@gmail.com>, DMARC lulus:
    Pengirim: nama tampilan "Prof." dari webmail gratis               12
    Link: tidak ada                                                     0
    Kata-kata: gift card 12 + pembuka BEC 10 + urgensi 7 + BEC 6 ...  dipotong 35
    Jumlah 47. Naskah gift card, pengirim tidak terverifikasi: minimal 60. Skor akhir 60,
    Suspicious email. (Dengan tanda tambahan, misalnya Reply-To, naiknya ke 70-an.)

  Reset password asli dari no-reply@westbrook.edu, DMARC lulus, link portal.westbrook.edu:
    Pengirim terverifikasi (universitas asli, terautentikasi)          0
    Link first-party, tanda lemah dihapus                               0
    Kata-kata: "reset your password" 10, "within 24 hours" 7, dibatasi 4 (benign cap)
    Umpan kredensial cocok, tetapi link aman: tanpa skor minimum. Skor akhir 4, LOW.

  Mailbox penuh dari admin@webmail-upgrade-center.com, link http://45.83.164.69/webmail/login:
    Pengirim: DMARC none 8 + DKIM none 7 + domain kata keamanan 10 + nama "Team" 12   35
    Link: IP mentah 28, path login pada domain jahat                                  30
    Kata-kata: mailbox penuh 8 + ancaman 8 + sign in 10 + salam generik 4 ...        dipotong 35
    Skor akhir 100, Likely scam.


4. TAB SCAN
--------------------------------------------------------------------------------------------

Tiga cara memasukkan sesuatu:

  Link         Tempel URL. Hasilnya salah satu dari tiga label:
                 Official domain match   domain ada di daftar trusted, skor 0. Untuk
                                         subdomain (lms.ntpu.edu.tw) tertulis "belongs to
                                         ntpu.edu.tw. We checked the address, not whether
                                         this page exists."
                 Suspicious link         ada tanda kuat (tiruan, link pendek, domain kata
                                         keamanan, IP mentah, punycode, TLD berisiko, trik
                                         "@", nama universitas dengan akhiran lain plus
                                         tanda login), skor selalu minimal 60
                 Unverified domain       tidak dikenal, belum tentu jahat
               Link tidak pernah berlabel "Likely scam"; label terkeras untuk link adalah
               "Suspicious link". Halaman login di domain yang tidak dikenal sengaja diberi
               "Unverified", karena layanan asli seperti canvas.instructure.com/login juga
               terlihat begitu.

               Salah ketik halaman login di domain asli (ssa.ntpu.edu.tw, bukan sso):
               berlabel Unverified, skor 40, dengan pesan "looks like a misspelling of
               sso.ntpu.edu.tw. Check the spelling." Tidak dicap Suspicious, karena hanya
               NTPU yang bisa membuat alamat berakhiran .ntpu.edu.tw; penyerang tidak bisa
               memasang halaman di sana. Bahayanya bukan penipuan, tetapi mahasiswa tidak
               sampai di halaman login yang dimaksud. Yang dibandingkan: sso, login, signin,
               portal, webmail, auth, ditambah subdomain dari CAMPUS_PORTAL_URL di .env bila
               diisi. Subdomain NTPU yang asli (www, my, lms, cof, sea.cc) tetap Official.

  Email PDF    Buka email, Print, Save as PDF, unggah (maks 5 MB). PDF dari "Microsoft Print
               to PDF" isinya gambar, ditolak dengan penjelasan. PDF tidak membawa header
               autentikasi dan kadang hanya menyimpan tulisan link, bukan tujuannya. Kedua
               hal itu dicatat di "What we couldn't check".

  Email file   Taruh (drop) file .eml di kotak teks, pilih lewat "browse your computer", atau
               tempel isi email. Teks tempelan tanpa header berarti pengirim tidak bisa
               diperiksa; link yang tersembunyi di balik "click here" juga tidak terlihat.
               File Word (.docx) tidak diterima: simpan emailnya sebagai PDF atau .eml.

"Try an example" di tiap mode:
  Link         Fake university login (Suspicious link), Fake PayPal (Suspicious link), Real
               university website www.ntpu.edu.tw (Official domain match), Misspelled
               sign-in page ssa.ntpu.edu.tw (Unverified, 40), Same name, wrong ending
               ntpu.com/login (Suspicious link), Unknown site (Unverified domain)
  Email PDF    Scam that hides instructions for scanners (Likely scam, 88), Scholarship that
               needs a fee first (Suspicious email, 75), Ordinary email (No red flags found)
  Email file   Delapan contoh: nomor 1, 2, 3, 5, 6 phishing (88 sampai 100, Likely scam),
               nomor 4 GitHub asli (0), nomor 7 dan 8 pengirim tidak terverifikasi (58 dan
               56, Unverified sender)

Setiap hasil berisi:
  Kartu ringkasan       label, temuan utama (apa yang diminta email ini), kenapa penting,
                        langkah berikutnya
  How we decided        rincian skor empat komponen, baris "Known scam script" bila ada,
                        kalimat yang disorot dari email, bukti dari tool, keyakinan
  What we couldn't      hal yang tidak bisa diperiksa. Makin banyak, makin rendah keyakinan.
  check

Catatan hijau "Checked with AI reasoning" atau catatan kuning dengan alasan AI tidak dipakai
selalu tampil, supaya pengguna tahu mode mana yang bekerja.

Memindai email atau PDF yang sama dua kali menaikkan skor 15 (memori kampanye, bagian 8).

Mode satu kampus (opsional, tiga baris di .env, contoh ada di .env.example):
  CAMPUS_NAME, CAMPUS_DOMAINS, CAMPUS_PORTAL_URL. Tanpa ketiganya aplikasi berjalan umum untuk
  universitas mana pun, dan itu sudah cukup untuk demo. Bila diisi (misalnya NTPU):
    - Domain yang hanya selisih satu atau dua huruf dari domain kampus (ntpuu.edu.tw,
      ntpu.org) dicap Suspicious.
    - Header menjadi "...for National Taipei University Students".
    - Tombol "Open official campus portal" muncul di hasil yang mencurigakan atau halaman login.
    - Salah ketik subdomain login dibandingkan juga dengan subdomain CAMPUS_PORTAL_URL.


5. TAB ANALYST
--------------------------------------------------------------------------------------------

Untuk juri teknis. Pilih contoh atau tempel email, lalu "Analyze (live stream)". Setiap langkah
agen muncul secara langsung:

  INPUT_SANITIZATION    email dibersihkan, link dan lampiran dihitung
  AGENT_FRAMEWORK       prompt dasar dan dua playbook dimuat
  TOOLS_EXECUTION       pemeriksa pengirim lalu pemindai link, dengan skor tiap komponen
  MEMORY_LOOKUP         pencarian sidik jari kampanye
  PATTERNS_MATCHED      naskah scam yang cocok dan skor minimumnya (bila ada)
  LLM_REASONING         prompt dirakit dan Gemini dipanggil
  LLM_FALLBACK          hanya tampil bila Gemini tidak dipakai, beserta alasannya
  COMPLETED             verdict, skor, waktu

Panel di bawahnya: empat ubin skor dan baris naskah scam, hasil pemeriksa pengirim dengan
lencana SPF/DKIM/DMARC, verdict tiap link, bukti dengan tanda "found in the email", catatan
sanitizer, dan memori kampanye. Tombol "Skill playbooks (.md)" memperlihatkan isi playbook yang
dipakai; tombol "Trusted domains" memperlihatkan dan mengubah daftar trusted.

Kotak "Use Gemini reasoning" menentukan apakah panggilan Gemini dicoba.


6. TAB EVALUATION DAN ANGKA SAAT INI
--------------------------------------------------------------------------------------------

6A. DATASET

  260 item sintetis: 130 phishing dan 130 aman, dari 5 universitas fiktif yang sengaja TIDAK
  ada di daftar trusted. Jenis input: 150 file .eml, 30 PDF, 20 teks tempelan, 60 link. Tiga
  tingkat kesulitan. Dibagi dua: dev 128 item (untuk menyetel) dan test 132 item (angka
  akhir). Bisa dibuat ulang persis sama dengan seed 42. Item aman sengaja dibuat mirip
  phishing: reset password asli, peringatan bank "unusual activity, sign in to review",
  pengingat tugas "submit immediately", tagihan Stripe "overdue".

6B. CARA MEMAKAI TAB INI

  Run the app on the dataset
    Pilih 10, 50, 100, 200 random atau All items, tekan Run. Aplikasi yang sedang berjalan
    menilai tiap item; semua angka di bawahnya dari run itu saja. Pilihan random selalu
    separuh phishing separuh aman dan tidak berulang selama tab browser terbuka. Tanpa
    Gemini, 260 item selesai dalam beberapa detik. "Use Gemini if available" mati secara
    bawaan karena tiap item satu panggilan Gemini.

  Right and wrong         caught, missed, false alarm, correctly allowed
  What the numbers mean   accuracy, precision, recall, F1 dengan kalimat penjelas
  By input type and       hasil per jenis input dan tingkat kesulitan
  difficulty
  Every item in this run  semua item dan jawaban aplikasi; centang "Only wrong answers";
                          klik baris untuk melihat alasannya
  Add items to the        tambah .eml, .pdf, .txt (maks 5 MB) atau link dengan label
  dataset                 Phishing/Legit. Disimpan di eval/added/, tidak ikut ke GitHub.

6C. ANGKA SAAT INI, MODE ATURAN, AMBANG 60

  Semua 260 item (All items)
    251 benar, 9 salah
    121 tertangkap, 9 lolos, 0 alarm palsu, 130 aman dibiarkan
    Accuracy 0.97, Precision 1.00, Recall 0.93, F1 0.96

  Sebelum perbaikan 13 November: 179 benar, 81 lolos, Recall 0.38.

  Laporan tersimpan (eval/results/latest/report.md, 122 item test)
    118 benar, 4 salah. Precision 1.000, Recall 0.934, F1 0.966
    Per jenis: email 73/76, PDF 15/16, teks tempelan 9/10, link 30/30
    Ambang 60 dipilih dari data dev (F1 dev 0.974), bukan dari data test.

  Model ML pembanding (TF-IDF + logistic regression, hanya alat ukur di folder eval)
    F1 0.948 pada jenis serangan yang sudah dikenal, 0.635 pada jenis yang belum pernah
    dilihat. Aturan pada 58 item yang sama: 0.980. Aturan tidak menghafal template.

  Uji generalisasi (16 email tulisan tangan di luar dataset, 8 scam dan 8 asli, termasuk
  bahasa Mandarin dan Indonesia): 16 dari 16 benar. Set kecil buatan tim, anggap sebagai
  gambaran saja.

  Catatan jujur: aturan 13 November dirancang setelah melihat item yang lolos di seluruh
  dataset (dev dan test). Jadi angka test di atas bukan lagi angka "belum pernah dilihat"
  untuk aturan itu. Aturannya ditulis dari mekanisme scam, bukan dari kalimat dataset, dan
  satu-satunya uji yang benar-benar terpisah adalah 16 email tulisan tangan tadi. Anggap
  angka test sebagai batas atas sampai ada data baru.

  Sembilan yang masih lolos, dan kenapa:
    6  "Your housing assignment is ready, kindly complete the form": tidak minta password,
       uang, atau data; pengirim lulus DMARC; link ke domain sendiri. Tidak ada yang bisa
       dibuktikan dari teks. Ini wilayah pembacaan makna (Gemini).
    1  Teks tempelan yang menampilkan alamat microsoft.com asli; link jahat yang sebenarnya
       tersembunyi di balik "click here" dan hilang saat ditempel.
    1  Teks tempelan dengan lampiran berbahaya; lampiran tidak ikut saat ditempel.
    1  Link campus-careers-hub.com/apply: domain netral tanpa tanda apa pun.

6D. ARTI ISTILAH

  TP tertangkap, FN lolos, FP alarm palsu, TN aman dibiarkan.
  Accuracy    (TP + TN) / semua       Precision   TP / (TP + FP)
  Recall      TP / (TP + FN)          F1          2 x P x R / (P + R)
  Contoh 260 item: Precision = 121 / (121 + 0) = 1.00. Recall = 121 / (121 + 9) = 0.93.
  Bagi mahasiswa, FN (scam yang lolos) adalah kesalahan paling berbahaya.

6E. YANG BOLEH DAN TIDAK BOLEH DIKATAKAN

  Boleh       "Pada 260 item sintetis, mesin aturan menangkap 93 persen scam tanpa satu pun
               alarm palsu, dan mengalahkan model ML pembanding pada jenis serangan baru."
  Boleh       "Lapisan AI sudah terpasang dan bisa diukur dengan perintah yang sama."
  Tidak boleh "AI kami akurat sekian persen." (belum diukur)
  Tidak boleh "Sudah diuji pada phishing nyata." (belum)


7. LAPISAN AI (GEMINI): APA YANG BERUBAH SAAT DINYALAKAN
--------------------------------------------------------------------------------------------

7A. CARA MENYALAKAN

  Salin .env.example menjadi .env, isi GEMINI_API_KEY, restart server. Chip kanan atas
  berubah menjadi "AI reasoning: on". Satu key berlaku untuk Scan, Analyst, dan Evaluation.
  Key tidak pernah sampai ke browser. Langkah lengkap di SETUP.md.

7B. YANG BERUBAH DAN YANG TIDAK

    Bagian                              Tanpa key           Dengan key
    ----------------------------------  ------------------  --------------------------------
    Pemeriksa pengirim                  kode                kode (sama)
    Pemindai link                       kode                kode (sama)
    Memori kampanye                     kode                kode (sama)
    Naskah scam dan skor minimum        kode                kode (sama)
    Komponen kata-kata                  aturan kata kunci   Gemini (maks 35)
    Kalimat bukti                       pencocokan pola     Gemini, dicek ke email
    Temuan utama di kartu hasil         template            Gemini
    Skor akhir                          hitungan            yang lebih besar antara hitungan
                                                            dan skor akhir Gemini
    Label dan skor link                 kode                kode (sama)
    Penjelasan link                     template            Gemini menulis ulang kalimatnya

  Gemini menerima: hasil keempat tool (termasuk daftar naskah scam yang cocok), kedua
  playbook, dan isi email yang dibungkus sebagai "data tidak dipercaya". Gemini menilai
  bagian kata-kata, mengutip kalimat, dan memberi skor akhirnya sendiri.

  Gemini bisa MENAIKKAN skor, tidak bisa menurunkannya di bawah hitungan aturan. Skor
  minimum naskah scam, lampiran executable, dan prompt injection tetap berlaku. Jadi mode
  AI tidak pernah lebih lemah dari mode aturan pada tanda-tanda teknis.

  Yang diharapkan dari Gemini: menangkap sisa yang tidak bisa dijangkau aturan, yaitu makna.
  Contoh: formulir "housing assignment" yang sopan, email berbahasa Mandarin atau Indonesia,
  variasi kalimat yang tidak ada di daftar kata kunci.

7C. PENGAMAN

  Kutipan dicek     setiap kutipan Gemini dicari di teks email; yang tidak ada dicoret dan
                    persentase "found in the email" ditampilkan
  Tidak bisa gagal  key kosong, ditolak, kena batas, lewat 30 detik, atau jawaban rusak:
  diam-diam         aturan mengambil alih, catatan kuning menyebut sebabnya, Analyst mencatat
                    LLM_FALLBACK
  Prompt injection  isi email diberi tanda data, bukan perintah; percobaan memerintah AI
                    ("ignore previous instructions") memaksa skor minimal 88
  Batas waktu       20 detik per percobaan, 30 detik total; rate limit dicoba ulang; model
                    pertama gemini-3-flash-preview, cadangan gemini-2.5-flash

  Sudah dites dengan key palsu: Google menjawab "API key not valid" dan aplikasi beralih ke
  aturan dalam kurang dari 1 detik. Pesan kuningnya saat ini masih teknis ("400
  INVALID_ARGUMENT").

7D. BIAYA DAN PRIVASI

  Satu panggilan per scan email/PDF, satu per scan link (untuk penjelasan saja), satu per
  item evaluasi bila "Use Gemini" dicentang. Dengan AI nyala, isi email dikirim ke Google;
  pakai email contoh, bukan email asli mahasiswa.

7E. CARA MENGUKUR AI

  Jalankan eval\run_eval.py dengan key terpasang. Baris llm_hybrid (aturan + Gemini) dan
  llm_only terisi di report.md pada 132 item test yang sama. Jawaban di-cache, jadi kalau
  kena batas harian bisa dilanjutkan besok. Sampai itu dilakukan, akurasi AI belum terukur.


8. MEMORI KAMPANYE DAN PRIVASI
--------------------------------------------------------------------------------------------

  - File campaign_memory.db di folder proyek.
  - Hanya hasil HIGH atau CRITICAL yang diingat. Email biasa tidak meninggalkan jejak.
  - Yang disimpan hanya sisi penyerang: domain pengirim, pola subjek (angka diganti #), dan
    sidik jari (hash) dari pengirim, subjek, dan domain link. Isi email, alamat pengirim
    lengkap, dan penerima tidak disimpan.
  - Pola yang sama datang lagi: +15. Contoh: PDF beasiswa 75 (Suspicious email) menjadi 90
    (Likely scam) pada scan kedua.
  - Panel Campaign memory di Analyst sudah berisi satu kampanye contoh (paypai-support.com).
    Kampanye contoh itu tidak cocok persis dengan email contoh PayPal, jadi scan pertama
    tetap +0; untuk memperlihatkan +15, scan email yang sama dua kali.
  - Tab Evaluation tidak menulis ke memori.
  - Mengulang demo dari awal: matikan server, hapus campaign_memory.db, nyalakan lagi.
  - Item yang ditambahkan di Evaluation disimpan di eval/added/, tidak ikut ke GitHub.


9. BATASAN YANG HARUS DIAKUI
--------------------------------------------------------------------------------------------

  - Data evaluasi sintetis. Belum diuji pada phishing nyata. Uji generalisasi hanya 16 email
    buatan tim sendiri, dan aturan terbaru dirancang setelah melihat kesalahan di seluruh
    dataset (lihat 6C).
  - Lapisan AI belum diukur dengan Gemini sungguhan, hanya diuji dengan jawaban tiruan.
  - Aturan buta terhadap makna: undangan sopan yang menipu tanpa permintaan apa pun lolos.
  - Kata kunci aturan hanya bahasa Inggris; email bahasa lain dinilai dari pengirim dan link.
  - PDF tidak membawa header; teks tempelan kehilangan link tersembunyi dan lampiran.
  - Pembuka "are you available?" dari teman asli yang kebetulan persis seperti naskah scam
    akan ditandai Suspicious. Sarannya: telepon orangnya.
  - Link pendek tidak diikuti; semua link pendek dianggap mencurigakan.
  - Daftar universitas disusun dari pengetahuan umum; cek domain yang penting bagi Anda di
    situs resmi universitasnya. Universitas yang tidak terdaftar tetap terlindungi oleh
    aturan tiruan generik dan aturan "nama universitas si penerima".


10. PERTANYAAN YANG MUNGKIN DITANYAKAN JURI
--------------------------------------------------------------------------------------------

"Di mana AI-nya?"
  Gemini membaca isi pesan, menilai manipulasinya, dan menjelaskan dengan kutipan. Di
  sekelilingnya ada agen yang menjalankan tool pengirim, link, memori, dan naskah scam.
  Tanpa key, bagian Gemini diganti aturan kata kunci, dan aplikasi mengatakannya.

"Kalau aturan saja sudah 93 persen, untuk apa Gemini?"
  Sisa 7 persen adalah scam yang sopan dan tanpa permintaan jelas, plus bahasa selain
  Inggris. Itu wilayah makna, yang tidak bisa ditulis sebagai kata kunci. Gemini dipasang
  untuk itu, dan pengukurannya sudah disiapkan.

"Bagaimana kalau Gemini mengarang?"
  Kutipan dicek ke teks email; yang tidak ada dicoret. Gemini tidak bisa menurunkan skor
  dari tool, dan skor minimum tetap berlaku.

"Bagaimana kalau emailnya berisi perintah untuk menipu AI?"
  Isi email diberikan sebagai data, bukan perintah. Percobaan prompt injection yang
  terdeteksi memaksa skor minimal 88.

"Bagaimana kamu tahu aturannya tidak hanya menghafal dataset?"
  Tiga bukti: aturannya ditulis dari mekanisme scam (gift card, biaya pencairan, ganti
  rekening), bukan dari kalimat dataset; model ML yang menghafal template jatuh ke F1 0.635
  pada jenis serangan baru sementara aturan 0.980; dan 16 email tulisan tangan di luar
  dataset, termasuk bahasa Mandarin dan Indonesia, 16 benar.

"Kenapa tidak ada alarm palsu?"
  Karena aturan dibangun di atas verifikasi: pengirim yang terbukti (universitas asli atau
  daftar trusted, lulus DMARC) dengan link ke domain sendiri tidak pernah kena skor minimum,
  seberapa pun mendesak kalimatnya. Skor minimum hanya berlaku saat pengirim atau link
  tidak bisa dijamin.

"Datanya dari mana?"
  Sintetis, dibuat sendiri dengan seed tetap. Lima universitas fiktif sengaja tidak masuk
  daftar trusted supaya tidak ada yang menguntungkan aturan.

"Apa yang disimpan dari email saya?"
  Email biasa tidak disimpan. Untuk scam, hanya domain penyerang dan pola subjeknya.
