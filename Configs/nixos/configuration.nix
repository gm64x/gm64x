# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      ./flatpak.nix
      ./home-config.nix
    ];

  # Bootloader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # Use latest kernel.
  boot.kernelPackages = pkgs.linuxPackages_latest;

  networking.hostName = "nixos"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables wireless support via wpa_supplicant.

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Enable networking
  networking.networkmanager.enable = true;

  # Set your time zone.
  time.timeZone = "America/Sao_Paulo";

  # Select internationalisation properties.
  i18n.defaultLocale = "en_US.UTF-8";

  i18n.extraLocaleSettings = {
    LC_ADDRESS = "pt_BR.UTF-8";
    LC_IDENTIFICATION = "pt_BR.UTF-8";
    LC_MEASUREMENT = "pt_BR.UTF-8";
    LC_MONETARY = "pt_BR.UTF-8";
    LC_NAME = "pt_BR.UTF-8";
    LC_NUMERIC = "pt_BR.UTF-8";
    LC_PAPER = "pt_BR.UTF-8";
    LC_TELEPHONE = "pt_BR.UTF-8";
    LC_TIME = "pt_BR.UTF-8";
  };

  # Enable the X11 windowing system.
  services.xserver.enable = true;

  # Enable the GNOME Desktop Environment.
  services.xserver.displayManager.gdm.enable = true;
  services.xserver.desktopManager.gnome.enable = true;

  # Configure keymap in X11
  services.xserver.xkb = {
    layout = "br";
    variant = "";
  };

  # Configure console keymap
  console.keyMap = "br-abnt2";

  # Enable CUPS to print documents.
  services.printing.enable = true;

  # Enable sound with pipewire.
  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
    # If you want to use JACK applications, uncomment this
    #jack.enable = true;

    # use the example session manager (no others are packaged yet so this is enabled by default,
    # no need to redefine it in your config for now)
    #media-session.enable = true;
  };

  # Enable touchpad support (enabled default in most desktopManager).
  # services.xserver.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  users.users.griot = {
    isNormalUser = true;
    description = "Gabriel Miguel";
    extraGroups = [ "networkmanager" "wheel" "docker" ];
    packages = with pkgs; [
        pkgs.thunderbird
	pkgs.vscode-fhs
	pkgs.ghostty
	pkgs.toolbox
    	pkgs.docker
    	pkgs.docker-client
    	pkgs.parsec-bin
    	pkgs.heynote
	pkgs.typst
    	pkgs.miktex
    	pkgs.direnv
    	pkgs.ente-auth
    	pkgs.git
    	pkgs.nano
    	pkgs.gnupg
    	pkgs.pass
	pkgs.uv
	pkgs.ruff
	pkgs.ollama
	pkgs.github-desktop
	pkgs.obsidian
	pkgs.vaults
	pkgs.gocryptfs
	pkgs.blender
	pkgs.krita
	pkgs.obs-studio
	pkgs.godot
	pkgs.steam
	pkgs.gimp3
	pkgs.refine
    	pkgs.gnome-extension-manager
    	pkgs.volta
    	pkgs.powershell
#	pkgs.home-manager
	pkgs.goofcord
	pkgs.gh
	pkgs.jdk24
	pkgs.jdk
	pkgs.dbeaver-bin
	pkgs.prs
	pkgs.font-manager
	pkgs.zed-editor-fhs
	pkgs.ptyxis
    ];
  };


   programs.steam = {
       enable = true;
	  remotePlay.openFirewall = true; 
	  	# Open ports in the firewall for Steam Remote Play
	  dedicatedServer.openFirewall = true; 
	  	# Open ports in the firewall for Source Dedicated Server
	  localNetworkGameTransfers.openFirewall = true; 
	  	# Open ports in the firewall for Steam Local Network Game Transfers
  };
  hardware.xone.enable = true; # support for the xbox controller USB dongle

  # Install firefox.
  programs.firefox.enable = true;
  
  #Activate tailscale
  #services.tailscale.enable = true;

  #add volta to path to all
  #  environment.sessionVariables = {
  #     PATH = "${config.environment.sessionVariables.PATH or ""}:/home/griot/.volta/bin";
  #};
	
  #Docker install preparation:
  virtualisation.docker.rootless = {
  	enable = true;
  	setSocketVariable = true;
  };

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
  #  vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #  wget
  ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "25.05"; # Did you read the comment?

#  programs.bash.enable = true;
   environment.sessionVariables = {
       PATH = "${pkgs.coreutils}/bin:${pkgs.findutils}/bin:/home/griot/.volta/bin";
   };

}
