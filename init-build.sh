# Create root project folder
mkdir -p graphql-base/{server/api,front-end}

# Navigate into backend
cd graphql-base/server

# # Create Python virtual environments
# python3.11 -m venv venv311
# python3.12 -m venv venv312

# Create backend files
touch config.py run.py requirements.txt
cd api
touch __init__.py schema.py routes.py models.py
cd ../..

# Inside your project root
mkdir -p front-end front-end-311 front-end-312

# Create both projects sequentially
cd front-end
npm create vite@latest . -- --template react
npm install &
wait

# Create both projects sequentially
cd front-end-311
npm create vite@latest . -- --template react

cd ../front-end-312
npm create vite@latest . -- --template react

# Now install dependencies in parallel
(cd front-end-311 && npm install) &
(cd front-end-312 && npm install) &
wait
