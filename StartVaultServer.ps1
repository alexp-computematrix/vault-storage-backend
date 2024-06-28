$ErrorActionPreference = "Stop";

$env:VAULT_CACERT=".\ca-cert.pem";


function StartServer {

    # ---- Check if vault server is started ---- #
    if (!(Get-Process -ProcessName "vault" -ErrorAction Ignore)) {

        # TODO(alexp): Create parameter for storage backend type in order to utilize targeted config

        # ---- Start Vault server with config ---- #
        Start-Process -FilePath "vault.exe" `
        -ArgumentList "server","-config",".\filesystem\config.hcl" `
        -ErrorAction Stop `
        -WindowStyle Hidden;
    };

};


function OperatorInit {

    # ---- Check if vault server has been initialized ---- #
    if (!(Get-ChildItem -Path ".\.vault\data\core" -ErrorAction Ignore)) {

        # ---- Initialize Vault ---- #
        & vault.exe operator init -format=json > keys.json;
    };

};


function OperatorUnseal {

    # ---- Parse keys data ---- #
    $KeysData = Get-Content -Path ".\keys.json" -Raw | ConvertFrom-Json;
    $UnsealKeys = $KeysData.unseal_keys_b64;
    $UnsealThreshold = $KeysData.unseal_threshold;

    # ---- Check if vault is sealed ---- #
    if( ((vault.exe status -format=json) | ConvertFrom-Json).sealed ) {

        # ---- Unseal vault using threshold ---- #
        $UnsealKeys[0..($UnsealThreshold-1)] | ForEach-Object {
            & vault.exe operator unseal $_ *> $null;
        };
    };

};


function Login {

    # ---- Parse keys data ---- #
    $KeysData = Get-Content -Path ".\keys.json" -Raw | ConvertFrom-Json;

    # ---- Perform login using root token ---- #
    & vault.exe login $KeysData.root_token *> $null;

};


function EnableKVSecretsEngine {

    param (
        [string]$path,
        [string]$desc
    );

    # ---- Enable KV secrets engine at $path ---- #
    & vault.exe secrets enable -path="$path" -description="$desc" kv *> $null;

};


try {

    StartServer;
    OperatorInit;
    OperatorUnseal;
    Login;
    EnableKVSecretsEngine -path "secret" -desc "key/value secret storage";

    Write-Output "Initialized Vault";
} catch {
    Write-Output "Vault initialization failed";
    exit 1;
}

exit 0;
