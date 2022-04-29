import sys,os,style

def banner():
    print(style.bold(style.green('____  __  ______  ___    ___  __  __  ______   _____   _____   _____  ______   ______       ')))
    print(style.bold(style.green('|  \ | |  | |   | | | __ | |  \ \/ /  | |__|| | | | |  | |__||  | |   | |   |  | |__||     ')))
    print(style.bold(style.green('| | \| |  | |-|   | |/  \| |   \  /   | |     | | | |  | |\ \   | |   | |-|    | |\ \  ')))
    print(style.bold(style.green('|_|  \_|  |_|___|  \__/\__/   /_/\_\  |_|     |_|_|_|  | | \_\  |_|   |_|___|  |_| \_\   ')))

def menu1():
    print(style.bold(style.green('[=============><============]')))
    print(style.bold(style.green('|   ',(style.blue('[1] Analyze Host/s')),'    |')))
    print(style.bold(style.green('|   ',(style.blue('[2] Analyze Network/s')),' |')))
    print(style.bold(style.green('|   ',(style.yellow('     [0] Exit')),'         |')))
    print(style.bold(style.green('[==============><===========]')))
    x=int(input(style.bold(style.red('[>] Your Choice : '))))
    return x

def blackbox():
    print(style.bold(style.yellow(" _____ __    _____ _____ _____ _____ _____ ")))
    print(style.bold(style.yellow("| __  |  |  |  _  |     |  |  | __  |     | _ _")))
    print(style.bold(style.yellow("| __ -|  |__|     |   --|    -| __ -|  |  ||_'_|")))
    print(style.bold(style.yellow("|_____|_____|__|__|_____|__|__|_____|_____||_,_|")))

def sublister():
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

    print("""%s                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s
    """ % (R, W, Y))


def devploit():
    print('''
                   ,                \033[96m
                   |'.             , ... Devploit \033[91m
                   |  '-._        / )
                 .'  .._  ',     /_'-,
                '   /  _'.'_\   /._)') \033[91m
               :   /  '_' '_'  /  _.'
               |E |   |Q| |Q| /   /
              .'  _\  '-' '-'    /
            .'--.(S     ,__` )  /
                  '-.     _.'  /      \033[92m
                __.--'----(   /
            _.-'     :   __\ /
           (      __.' :'  :Y
            '.   '._,  :   :|        \033[96m
              '.     ) :.__:|
                \    \______/
                 '._L/_H____]     ''')

def d_tect():
    print(style.bold(style.magenta("  ____   _____ _____ ____ _____ ")))
    print(style.bold(style.magenta(" |  _ \ |_   _| ____/ ___|_   _|")))
    print(style.bold(style.magenta(" | | | |__| | |  _|| |     | |  ")))
    print(style.bold(style.magenta(" | |_| |__| | | |__| |___  | |  ")))
    print(style.bold(style.magenta(" |____/   |_| |_____\____| |_|  v1.0")))
    print(style.bold(style.magenta("")))

def analyze_host():
    print(style.bold(style.magenta("  ____  ___ __    ____          ")))
    print(style.bold(style.magenta(" | |_| ||\ | | |     ")))
    print(style.bold(style.magenta(" |_| | || \|              ")))
