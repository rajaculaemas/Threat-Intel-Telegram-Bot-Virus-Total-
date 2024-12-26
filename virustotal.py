import requests
import json
import sys

# Gantilah dengan API Key Anda
API_KEY = '<Your Virus Total API key>'

# Endpoint URL untuk mendapatkan detail analisis berdasarkan IP
def create_url(ip_address):
    return f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'

# Headers untuk autentikasi menggunakan API Key
headers = {
    'x-apikey': API_KEY
}

# Fungsi untuk mengirim request ke API VirusTotal dan mendapatkan hasil analisis IP
def get_ip_analysis(ip):
    url = create_url(ip)
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Mendapatkan data dari response JSON
        data = response.json().get('data', {})
        attributes = data.get('attributes', {})
        
        # Ambil hasil analisis dari field last_analysis_results
        analysis_results = attributes.get('last_analysis_results', {})

        # Inisialisasi hitungan untuk kategori hasil analisis
        malicious_count = 0
        suspicious_count = 0
        unrated_count = 0
        phishing_count = 0
        malware_count = 0
        clean_count = 0

        # Periksa setiap hasil analisis dari engine
        for engine, result in analysis_results.items():
            result_value = result.get('result', 'N/A')
            if result_value == 'malicious':
                malicious_count += 1
            elif result_value == 'suspicious':
                suspicious_count += 1
            elif result_value == 'unrated':
                unrated_count += 1
            elif result_value == 'phishing':
                phishing_count += 1
            elif result_value == 'malware':
                malware_count += 1
            elif result_value == 'clean':
                clean_count += 1

        # Ambil tags
        tags = attributes.get('tags', [])

        # Kembalikan hasil analisis dalam bentuk teks yang mudah dibaca
        result_text = (
            f"Hasil analisis dari {len(analysis_results)} engine:\n"
            f"malicious: {malicious_count}\n"
            f"suspicious: {suspicious_count}\n"
            f"unrated: {unrated_count}\n"
            f"phishing: {phishing_count}\n"
            f"malware: {malware_count}\n"
            f"clean: {clean_count}\n"
            f"tags: {', '.join(tags)}\n"
        )
        return result_text

    else:
        # Jika error, kembalikan pesan error
        return f"Error: {response.status_code}\n{response.text}"

# Panggil fungsi dengan IP dari argumen
if __name__ == "__main__":
    # Mengambil IP dari argumen yang diberikan saat menjalankan skrip
    ip_address = sys.argv[1]
    result = get_ip_analysis(ip_address)
    print(result)  # Cetak hasil ke stdout
#    print("-" * 20) #Cetak "-" 20 kali
