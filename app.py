import os
from flask import Flask, after_this_request, render_template, request, redirect, url_for, flash, send_file, make_response, session
import secrets
import uuid
from utils import crypto_logic, prime_utils
import math
import random
import io
import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMP_FOLDER'] = 'temp_downloads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['TEMP_FOLDER'], exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB limit for uploads

SCRIPT_START_TIME = datetime.datetime.now()

@app.context_processor
def inject_script_start_time():
    return dict(SCRIPT_START_TIME=SCRIPT_START_TIME)


def is_prime(n):
    return prime_utils.is_prime(n)

def power(base, exp, mod):
    return pow(base, exp, mod)

def gcd(a, b):
    return math.gcd(a, b)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(e, phi):
    d, x, y = extended_gcd(e, phi)
    if d != 1:
        return None 
    return x % phi

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/xor_cipher', methods=['GET', 'POST'])
def xor_cipher_route():
    context = {}
    if request.method == 'POST':
        try:
            key = request.form.get('key_xor', '')
            input_type = request.form.get('input_type_xor', 'text')
            
            context.update({
                'current_key_xor': key,
                'current_input_type_xor': input_type
            })

            if not key:
                flash('Key is required for XOR Cipher.', 'danger')
                return render_template('xor_cipher.html', **context)

            input_data_bytes = b''
            original_filename = "xor_processed_data.dat" # Default output filename

            if input_type == 'text':
                text_data = request.form.get('input_text_xor', '')
                if not text_data:
                    flash('Input text is required for "Text" type.', 'danger')
                    return render_template('xor_cipher.html', **context)
                input_data_bytes = text_data.encode('utf-8', errors='replace')
                context['current_input_text_xor'] = text_data
            else: # file
                file = request.files.get('input_file_xor')
                if not file or file.filename == '':
                    flash('File is required for "File" type.', 'danger')
                    return render_template('xor_cipher.html', **context)
                input_data_bytes = file.read()
                original_filename = f"xor_{file.filename}"
            
            processed_bytes, byte_details = crypto_logic.xor_cipher_process(input_data_bytes, key)
            context['byte_details_xor'] = byte_details if input_type == 'text' and len(input_data_bytes) < 256 else None

            if input_type == 'text':
                try:
                    context['output_text_xor'] = processed_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    context['output_text_xor'] = processed_bytes.hex()
                    flash("Output data is not valid UTF-8, shown as hex.", "warning")
            else: # file
                # Instead of immediately returning the file:
                # file_stream = io.BytesIO(processed_bytes)
                # response = make_response(send_file(file_stream, as_attachment=True, download_name=original_filename))
                # response.headers["Content-Disposition"] = f"attachment; filename={original_filename}"
                # flash(f"File '{original_filename}' processed and ready for download.", "success")
                # return response
    
                # Store the file and provide a download link:
                if 'download_tokens' not in session:
                    session['download_tokens'] = []
                    
                # Generate a unique token for this download
                download_token = secrets.token_urlsafe(16)
                session['download_tokens'].append(download_token)
                
                # Save the file temporarily
                temp_filepath = os.path.join(app.config['TEMP_FOLDER'], download_token)
                with open(temp_filepath, 'wb') as f:
                    f.write(processed_bytes)
                
                # Add download URL to context
                download_url = url_for('download_file', filename=original_filename, token=download_token)
                context['download_url'] = download_url
                context['download_filename'] = original_filename
                
                flash(f"File '{original_filename}' processed successfully. Click the download button below.", "success")
                
        except ValueError as ve:
            flash(f'XOR Cipher Error: {str(ve)}', 'danger')
        except Exception as e:
            flash(f'An unexpected error occurred: {str(e)}', 'danger')
            
    return render_template('xor_cipher.html', **context)


@app.route('/caesar_cipher', methods=['GET', 'POST'])
def caesar_cipher_route():
    context = {}
    if request.method == 'POST':
        try:
            shift_values_str = request.form.get('shift_values_caesar', '')
            operation = request.form.get('operation_caesar', 'encrypt')
            input_type = request.form.get('input_type_caesar', 'text')

            context.update({
                'current_shifts_caesar': shift_values_str,
                'current_operation_caesar': operation,
                'current_input_type_caesar': input_type
            })

            if not shift_values_str:
                flash('Shift values are required.', 'danger')
                return render_template('caesar_cipher.html', **context)
            
            try:
                shifts = [int(s.strip()) for s in shift_values_str.split(',') if s.strip().lstrip('-').isdigit()]
                if not shifts: # Also check if string was just "abc" or empty after split
                     if any(c.isalpha() for c in shift_values_str): # Check if it contained non-digits
                         raise ValueError("Shift values must be numbers (e.g., '3' or '2,-4,3').")
                     shifts = [int(s) for s in shift_values_str if s.isdigit() or (s.startswith('-') and s[1:].isdigit())] # Fallback for single number strings like "2432"
                if not shifts: # Final check
                    raise ValueError("Shift values must contain valid integers.")
            except ValueError as e:
                flash(f'Invalid shift values: {str(e)}. Must be comma-separated integers (e.g., "3" or "2,-4,3,2").', 'danger')
                return render_template('caesar_cipher.html', **context)

            input_data_bytes = b''
            original_filename = "caesar_processed_data.dat"

            if input_type == 'text':
                text_data = request.form.get('input_text_caesar', '')
                if not text_data:
                    flash('Input text is required for "Text" type.', 'danger')
                    return render_template('caesar_cipher.html', **context)
                input_data_bytes = text_data.encode('utf-8', errors='replace') # UTF-8 for text, then process bytes
                context['current_input_text_caesar'] = text_data

                processed_bytes, char_details = crypto_logic.caesar_cipher_process(input_data_bytes, shifts, operation)
                context['char_details_caesar'] = char_details if len(input_data_bytes) < 256 else None

                try:
                    context['output_text_caesar'] = processed_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    context['output_text_caesar'] = processed_bytes.hex()
                    flash("Output data is not valid UTF-8 after Caesar byte shift, shown as hex.", "warning")

            else:  # file
                file = request.files.get('input_file_caesar')
                if not file or file.filename == '':
                    flash('File is required for "File" type.', 'danger')
                    return render_template('caesar_cipher.html', **context)
                input_data_bytes = file.read()
                original_filename = f"caesar_{file.filename}"

                processed_bytes, char_details = crypto_logic.caesar_cipher_process(input_data_bytes, shifts, operation)
                # Optionally, you can add char_details to context for small files

                if 'download_tokens' not in session:
                    session['download_tokens'] = []

                download_token = secrets.token_urlsafe(16)
                session['download_tokens'].append(download_token)

                temp_filepath = os.path.join(app.config['TEMP_FOLDER'], download_token)
                with open(temp_filepath, 'wb') as f:
                    f.write(processed_bytes)

                download_url = url_for('download_file', filename=original_filename, token=download_token)
                context['download_url'] = download_url
                context['download_filename'] = original_filename

                flash(f"File '{original_filename}' processed successfully. Click the download button below.", "success")
                return render_template('caesar_cipher.html', **context)

        except ValueError as ve:
            flash(f'Caesar Cipher Error: {str(ve)}', 'danger')
        except Exception as e:
            flash(f'An unexpected error occurred: {str(e)}', 'danger')
            import traceback
            traceback.print_exc()


    return render_template('caesar_cipher.html', **context)

@app.route('/diffie_hellman', methods=['GET', 'POST'])
def diffie_hellman_route():
    context = {}
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            p_val_str = request.form.get('prime_p', '')
            g_val_str = request.form.get('generator_g', '')
            private_key_val_str = request.form.get('private_key', '')
            received_public_key_str = request.form.get('received_public_key', '')

            p_val = int(p_val_str) if p_val_str.isdigit() else None
            g_val = int(g_val_str) if g_val_str.isdigit() else None
            private_key_val = int(private_key_val_str) if private_key_val_str.isdigit() else None
            
            context.update({
                'p_val': p_val, 'g_val': g_val, 'private_key_val': private_key_val,
                'received_public_key_form': received_public_key_str # Keep string for re-populating form
            })

            if not (p_val and g_val and private_key_val):
                flash('Prime (p), Generator (g), and your Private Key are required as numbers for key generation.', 'warning')
            elif not is_prime(p_val):
                flash(f'{p_val} is not a prime number.', 'danger')
                context['p_error'] = True
            else:
                public_key = power(g_val, private_key_val, p_val)
                context['public_key'] = public_key
                flash(f'Your public key: {public_key}', 'success')

                if action == 'send_message' or action == 'receive_message':
                    message = request.form.get('message_text', '')
                    received_public_key = int(received_public_key_str) if received_public_key_str.isdigit() else None
                    context['message_text'] = message
                    
                    if received_public_key is None: # check for None explicitly
                        flash('Partner\'s Public Key is required as a number for messaging.', 'warning')
                    elif not message:
                        flash('Message cannot be empty.', 'warning')
                    else:
                        shared_secret = power(received_public_key, private_key_val, p_val)
                        context['shared_secret_debug'] = shared_secret 
                        
                        # Using XOR for simplicity with the shared secret as key
                        message_bytes = message.encode('utf-8', errors='replace')
                        processed_message_bytes, _ = crypto_logic.xor_cipher_process(message_bytes, str(shared_secret))
                        
                        try:
                            processed_message_text = processed_message_bytes.decode('utf-8', errors='replace')
                        except:
                            processed_message_text = processed_message_bytes.hex()


                        if action == 'send_message':
                            context['sent_encrypted_message'] = processed_message_text
                            flash('Message processed with shared secret.', 'info')
                        elif action == 'receive_message': 
                            context['received_decrypted_message'] = processed_message_text
                            flash('Ciphertext processed with shared secret.', 'info')
        
        except ValueError: # Catches int conversion errors if non-digits were submitted for numeric fields
            flash('Invalid numeric input for p, g, private key, or partner\'s public key.', 'danger')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            
    return render_template('diffie_hellman.html', **context)


@app.route('/rsa_cipher', methods=['GET', 'POST'])
def rsa_cipher_route():
    context = {}
    if request.method == 'POST':
        action = request.form.get('action')
        
        try:
            if action == 'generate_keys':
                p_str = request.form.get('prime_p_rsa', '')
                q_str = request.form.get('prime_q_rsa', '')
                e_input_str = request.form.get('e_rsa', '')

                p = int(p_str) if p_str.isdigit() else None
                q = int(q_str) if q_str.isdigit() else None
                
                context.update({'p_rsa': p, 'q_rsa': q, 'e_rsa_input': e_input_str})

                if p is None or q is None: # Check for None
                    flash('Prime numbers p and q are required and must be integers.', 'danger')
                elif not is_prime(p):
                    flash(f'{p} is not a prime number.', 'danger')
                    context['p_rsa_error'] = True
                elif not is_prime(q):
                    flash(f'{q} is not a prime number.', 'danger')
                    context['q_rsa_error'] = True
                elif p == q:
                    flash('p and q cannot be the same.', 'danger')
                else:
                    n = p * q
                    phi_n = (p - 1) * (q - 1)
                    context.update({'n_rsa': n, 'phi_n_rsa': phi_n})

                    e = None
                    if e_input_str:
                        if e_input_str.isdigit():
                            e_candidate = int(e_input_str)
                            if not (1 < e_candidate < phi_n and gcd(e_candidate, phi_n) == 1):
                                flash(f'Provided e={e_candidate} is not valid. It must be 1 < e < {phi_n} and coprime to {phi_n}. Will attempt auto-selection.', 'warning')
                            else:
                                e = e_candidate
                        else:
                            flash('Invalid format for e. Must be an integer. Will attempt to auto-select.', 'warning')
                    
                    if e is None: 
                        possible_es = [65537, 257, 17, 5, 3]
                        for val_e in possible_es:
                            if 1 < val_e < phi_n and gcd(val_e, phi_n) == 1:
                                e = val_e
                                break
                        if e is None: 
                           for val_e_candidate in range(3, min(phi_n, 1000), 2): # Limit search for practical reasons
                               if gcd(val_e_candidate, phi_n) == 1:
                                   e = val_e_candidate
                                   break
                        if e is None:
                            flash('Could not automatically find a suitable e. Try different p, q, or provide a valid e.', 'danger')
                            return render_template('rsa_cipher.html', **context)
                    
                    context['e_rsa_gen'] = e
                    d = mod_inverse(e, phi_n)

                    if d is None:
                        flash(f'Could not compute d for e={e} and phi_n={phi_n}. This indicates an issue with e selection relative to phi_n.', 'danger')
                    else:
                        context.update({
                            'd_rsa': d,
                            'public_key_rsa': f'e={e}, n={n}',
                            'private_key_rsa': f'd={d}, n={n}'
                        })
                        flash(f'Keys generated: Public(e={e}, n={n}), Private(d={d}, n={n})', 'success')
            
            elif action == 'encrypt_rsa':
                message = request.form.get('message_rsa', '')
                e_enc_str = request.form.get('e_encrypt_rsa', '')
                n_enc_str = request.form.get('n_encrypt_rsa', '')

                e_enc = int(e_enc_str) if e_enc_str.isdigit() else None
                n_enc = int(n_enc_str) if n_enc_str.isdigit() else None

                context.update({
                    'message_rsa_enc': message, 
                    'e_encrypt_rsa_val': e_enc, 
                    'n_encrypt_rsa_val': n_enc
                })

                if not message or e_enc is None or n_enc is None:
                    flash('Message, e, and n are required for encryption and must be valid integers.', 'danger')
                else:
                    public_key = (e_enc, n_enc)
                    ciphertext_nums, ciphertext_str = crypto_logic.rsa_encrypt_process(message, public_key)
                    context.update({
                        'ciphertext_nums_rsa': ciphertext_nums,
                        'ciphertext_str_rsa': ciphertext_str,
                        'message_bytes_rsa': [ord(c) for c in message]
                    })
                    flash('Message encrypted.', 'info')

            elif action == 'decrypt_rsa':
                ciphertext_input = request.form.get('ciphertext_rsa', '')
                d_dec_str = request.form.get('d_decrypt_rsa', '')
                n_dec_str = request.form.get('n_decrypt_rsa', '')

                d_dec = int(d_dec_str) if d_dec_str.isdigit() else None
                n_dec = int(n_dec_str) if n_dec_str.isdigit() else None

                context.update({
                    'ciphertext_rsa_dec': ciphertext_input, 
                    'd_decrypt_rsa_val': d_dec, 
                    'n_decrypt_rsa_val': n_dec
                })

                if not ciphertext_input or d_dec is None or n_dec is None:
                    flash('Ciphertext, d, and n are required for decryption and must be valid integers.', 'danger')
                else:
                    private_key = (d_dec, n_dec)
                    try:
                        # Expect ciphertext_input as list of ints: "[1275, 1135, ...]" or "1275, 1135, ..."
                        cleaned_input = ciphertext_input.strip().lstrip('[').rstrip(']')
                        if not cleaned_input: raise ValueError("Ciphertext input is empty.")
                        ciphertext_to_process = [int(x.strip()) for x in cleaned_input.split(',')]
                        
                        decrypted_message = crypto_logic.rsa_decrypt_process(ciphertext_to_process, private_key)
                        context['decrypted_message_rsa'] = decrypted_message
                        flash('Ciphertext decrypted.', 'info')
                    except ValueError as ve:
                        flash(f'Invalid ciphertext format for decryption. Ensure it is a comma-separated list of numbers (e.g., "123, 456" or "[123, 456]"). Error: {ve}', 'danger')
                    except Exception as e_dec:
                         flash(f'Decryption error: {str(e_dec)}', 'danger')

        except ValueError as ve_outer: # Catch general int conversion errors if not handled specifically
            flash(f'Invalid numeric input for RSA parameters: {str(ve_outer)}', 'danger')
        except Exception as e:
            flash(f'An RSA error occurred: {str(e)}', 'danger')
            import traceback
            traceback.print_exc()
            
    return render_template('rsa_cipher.html', **context)


@app.route('/block_cipher', methods=['GET', 'POST'])
def block_cipher_route():
    context = {
        'block_sizes': [8, 16, 32, 64, 128], # in bits
        'padding_modes': ['CMS', 'Null', 'Space', 'RandomBits'] 
    }
    if request.method == 'POST':
        try:
            block_size_bits = int(request.form.get('block_size', 128)) # Default to 128 bits (16 bytes)
            padding_mode = request.form.get('padding_mode', 'CMS')
            key = request.form.get('key_block', '')
            operation = request.form.get('operation_block', 'encrypt') 
            input_type = request.form.get('input_type_block', 'text') 
            
            show_details = 'show_details_block' in request.form
            
            context.update({
                'current_block_size': block_size_bits,
                'current_padding_mode': padding_mode,
                'current_key_block': key,
                'current_operation_block': operation,
                'current_input_type_block': input_type,
                'current_show_details': show_details
            })

            if not key:
                flash('Key is required for Block Cipher.', 'danger')
                return render_template('block_cipher.html', **context)

            input_data_bytes = b''
            original_filename = f"{operation}ed_data.dat"

            if input_type == 'text':
                text_data = request.form.get('input_text_block', '')
                if not text_data:
                    flash('Input text is required if "Text" input type is selected.', 'danger')
                    return render_template('block_cipher.html', **context)
                input_data_bytes = text_data.encode('utf-8', errors='replace')
                context['current_input_text_block'] = text_data
            else: # input_type == 'file'
                # Store the file and provide a download link:
                if 'download_tokens' not in session:
                    session['download_tokens'] = []
                    
                # Generate a unique token for this download
                download_token = secrets.token_urlsafe(16)
                session['download_tokens'].append(download_token)
                
                # Save the file temporarily
                temp_filepath = os.path.join(app.config['TEMP_FOLDER'], download_token)
                with open(temp_filepath, 'wb') as f:
                    f.write(processed_data_bytes)
                
                # Add download URL to context
                download_url = url_for('download_file', filename=original_filename, token=download_token)
                context['download_url'] = download_url
                context['download_filename'] = original_filename
                
                flash(f"File '{original_filename}' processed successfully. Click the download button below.", "success")
                return render_template('block_cipher.html', **context)

            processed_data_bytes, details = crypto_logic.block_cipher_process(
                data=input_data_bytes,
                key_str=key,
                block_size_bits=block_size_bits,
                padding_mode=padding_mode,
                operation=operation,
                show_details=show_details
            )

            context['details_block'] = details if show_details else None

            if input_type == 'text':
                try:
                    context['output_text_block'] = processed_data_bytes.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                     context['output_text_block'] = processed_data_bytes.hex() 
                     flash("Output data is not valid UTF-8, shown as hex.", "warning")
            else: # input_type == 'file'
                # Store the file and provide a download link:
                if 'download_tokens' not in session:
                    session['download_tokens'] = []
                    
                # Generate a unique token for this download
                download_token = secrets.token_urlsafe(16)
                session['download_tokens'].append(download_token)
                
                # Save the file temporarily
                temp_filepath = os.path.join(app.config['TEMP_FOLDER'], download_token)
                with open(temp_filepath, 'wb') as f:
                    f.write(processed_data_bytes)
                
                # Add download URL to context
                download_url = url_for('download_file', filename=original_filename, token=download_token)
                context['download_url'] = download_url
                context['download_filename'] = original_filename
                
                flash(f"File '{original_filename}' processed successfully. Click the download button below.", "success")
                return render_template('block_cipher.html', **context)

        except ValueError as ve:
            flash(f'Block Cipher Error: {str(ve)}', 'danger')
        except Exception as e:
            flash(f'A Block Cipher error occurred: {str(e)}', 'danger')
            import traceback
            traceback.print_exc()

    return render_template('block_cipher.html', **context)

@app.route('/hashing_functions', methods=['GET', 'POST'])
def hashing_functions_route():
    context = {
        'hash_algorithms': ['md5', 'sha1', 'sha256', 'sha512']
    }
    if request.method == 'POST':
        try:
            algorithm = request.form.get('hash_algorithm', 'sha256')
            input_type = request.form.get('input_type_hash', 'text')
            
            context.update({
                'current_algorithm_hash': algorithm,
                'current_input_type_hash': input_type
            })

            input_data_bytes = b''

            if input_type == 'text':
                text_data = request.form.get('input_text_hash', '')
                # Allow empty text for hashing
                input_data_bytes = text_data.encode('utf-8', errors='replace')
                context['current_input_text_hash'] = text_data
            else: # file
                file = request.files.get('input_file_hash')
                if not file or file.filename == '':
                    flash('File is required if "File" input type is selected for hashing.', 'danger')
                    return render_template('hashing_functions.html', **context)
                input_data_bytes = file.read()
                context['original_filename_hash'] = file.filename
            
            hex_digest = crypto_logic.hash_data(input_data_bytes, algorithm)
            context['hash_digest'] = hex_digest
            flash(f"{algorithm.upper()} hash calculated successfully.", "success")

        except ValueError as ve:
            flash(f'Hashing Error: {str(ve)}', 'danger')
        except Exception as e:
            flash(f'An unexpected error occurred during hashing: {str(e)}', 'danger')
            import traceback
            traceback.print_exc()
            
    return render_template('hashing_functions.html', **context)

@app.route('/download/<filename>/<token>', methods=['GET'])
def download_file(filename, token):
    """Handle secure file downloads with a token validation"""
    if 'download_tokens' not in session or token not in session['download_tokens']:
        flash('Invalid or expired download link.', 'danger')
        return redirect(url_for('index'))
        
    file_path = os.path.join(app.config['TEMP_FOLDER'], token)
    if not os.path.exists(file_path):
        flash('Download file not found. It may have expired.', 'danger')
        return redirect(url_for('index'))
    
    # Remove the token from session after use
    session['download_tokens'].remove(token)
    
    # Send the file and then delete it
    @after_this_request
    def remove_file(response):
        try:
            os.remove(file_path)
        except Exception as e:
            app.logger.error(f"Error removing temporary file {file_path}: {e}")
        return response
        
    return send_file(file_path, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
