#!/bin/bash

#creates a cluster based on a dockerfile,
function create_cluster {
    id=$1
    dockerfile_path=$2
    instances=$3
    package=$4
    mem=$5
    volume_size=$6
    ip=$7
    if [ ! -z "$8" ]; then
        port=$8
    else
        port=0
    fi
    dockerfile_content="$(cat -A "$dockerfile_path")"
    dockerfile_content=$(sed 's/\$/\\n/g' <<< $dockerfile_content)
    dockefile_content=$dockerfile_content
    echo "ip is "$ip 
    curl -O -i -X POST -F "id=$id" -F "dockerfile=$dockerfile_content" -F "instances=$instances" -F "package=@$package" -F "mem=$mem" -F "volume_size=$volume_size" -F "port=$port" $ip"/create_cluster"
}

#adds an instance to an existing cluster
function add_instance {
    image_id=$1
    mem=$2
    port=$3
    ip=$4
    curl -O -i -X POST -F "image_id=$image_id" -F "mem=$mem" -F "port=$port" $ip'/add'
}

#removes a container instances by its id
function remove_instance {
    echo "pixei aqui. Sai correndo"
    instance_id=$1
    ip=$2
    curl -i -XDELETE ${ip}'/remove_instance/'$instance_id
}

#removes an image by its id
function remove_image {
    image_id=$1
    ip=$2
    curl -i -XDELETE ${ip}'/remove_image/'$image_id
}

#lists instances created
function list_instances {
    image_id=$1
    ip=$2
    curl -i -XGET ${ip}'/list/'$image_id
}

#lists available images
function list_images {
    ip=$1
    curl -i -XGET ${ip}'/image_list'
}

#creates a cluster that serves clients exclusively
function create_single_client_cluster {
    id=$1
    dockerfile_path=$2
    package=$3
    mem=$4
    volume_size=$5
    ip=$6
    dockerfile_content="$(cat -A "$dockerfile_path")"
    dockerfile_content=$(sed 's/\$/\\n/g' <<< $dockerfile_content)
    dockerfile_content=$dockerfile_content
    curl -i -X POST -F "id=$id" -F "dockerfile=$dockerfile_content" -F "package=@$package" -F "mem=$mem" -F "volume_size=$volume_size" ${ip}'/create_single_client_cluster'
}


count=0            
            
#parsing options
while getopts ":c:v:r:m:li:a:s:" opt; do
    case $opt in
        c)
            create_params+=($OPTARG) 

            if [ ${#create_params[@]} -eq 8 ]; then
                create_cluster ${create_params[0]} ${create_params[1]} ${create_params[2]} ${create_params[3]} ${create_params[4]} ${create_params[5]} ${create_params[6]} ${create_params[7]}
            fi
        ;;
        r)
            rm_params+=($OPTARG)
            if [ ${#rm_params[@]} -eq 2 ]; then
                remove_instance ${rm_params[0]} ${rm_params[1]}
            fi
        ;;
        m)
            rmi_params+=($OPTARG)
            if [ ${#rmi_params[@]} -eq 2 ]; then
                remove_image ${rmi_params[0]} ${rmi_params[1]}
            fi
        ;;
        l)
            list_inst_params+=($OPTARG)
            if [ ${list_inst_params[@]} -eq 2 ]; then
                 list_instances ${list_inst_params[0]} ${list_inst_params[1]}
            fi
        ;;
        i)
            ip=($OPTARG)
            list_images $ip
        ;;
        a)
            add_params+=($OPTARG)
            if [ ${#add_params[@]} -eq 4 ]; then
                add_instance ${add_params[0]} ${add_params[1]} ${add_params[2]} ${add_params[3]}
            fi
        ;;
        s)
           create_single_params+=($OPTARG)
           if [ ${#create_single_params[@]} -eq 5 ]; then
               create_single_client_cluster ${create_single_params[0]} ${create_single_params[1]} ${create_single_params[2]} ${create_single_params[3]} ${create_single_params[4]}
           fi
    esac
done
