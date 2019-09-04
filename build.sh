#!/bin/sh

case $1 in
        "usage" )
                echo "Usage:"
                echo "        ./build                - Build by default mode."
                echo "        ./build debug          - Build Debug mode."
                echo "        ./build release        - Build Release mode."
                echo "        ./build clean          - Clean all objects files."
                ;;
        "debug" )
#                rm -Rf obj
                mkdir -p obj
                cd obj
                cmake -DCMAKE_BUILD_TYPE=Debug ../ && make
                cd ..
                ;;
        "release" )
                rm -Rf obj
                mkdir -p obj
                cd obj
                cmake -DCMAKE_BUILD_TYPE=Release ../ && make
                cd ..
                ;;
        "clean" )
                cd obj
                make clean
                cd ..
                ;;
        * )
                if [ ! -d "obj" ]; then
                    $0 debug
                else
                    cd obj
                    make
                    cd ..
                fi
                ;;
esac

echo "Build end"
exit 0

