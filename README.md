# BlackoutGuard - Power Grid Cybersecurity System


# Alunos
Gustavo Vegi / RM550188 Pedro Henrique Silva de Morais / RM98804



## Project Overview
BlackoutGuard is a comprehensive cybersecurity solution designed to protect power grid infrastructure from cyber attacks and monitor for vulnerabilities that could lead to power outages. The system provides real-time monitoring, threat detection, incident response capabilities, and analytical tools to help utilities maintain grid stability and security.

## Problem Statement
Power grids are increasingly targeted by sophisticated cyber attacks that can cause widespread blackouts, infrastructure damage, and public safety risks. Traditional security systems are often reactive and lack specialized tools to address the unique challenges of power grid cybersecurity. BlackoutGuard fills this gap by providing a specialized solution for monitoring, detecting, and responding to cyber threats in power grid environments.

## Key Features

## Funcionalidades Principais

- **Autenticação e Controle de Acesso**: Sistema de login seguro com controle de acesso baseado em funções
- **Monitoramento de Ameaças**: Detecção e análise de ameaças cibernéticas
- **Gestão de Incidentes**: Fluxo completo de registro, acompanhamento e resolução de incidentes
- **Avaliação de Vulnerabilidades**: Identificação e classificação de vulnerabilidades com CVSS
- **Sistema de Alertas**: Notificações prioritárias para eventos críticos
- **Logs e Auditoria**: Rastreamento detalhado de atividades para análise forense

## Capturas de Tela

### Autenticação e Registro

<div style="display: flex; justify-content: space-between;">
  <div style="flex: 1; margin-right: 10px;">
    <img src="image-3.png" alt="Tela de Login" width="100%">
    <p align="center"><i>Tela de Login</i></p>
  </div>
  <div style="flex: 1; margin-left: 10px;">
    <img src="image-4.png" alt="Registro de Usuário" width="100%">
    <p align="center"><i>Registro de Novo Usuário</i></p>
  </div>
</div>

### Gestão de Segurança

<div style="display: flex; flex-wrap: wrap; justify-content: space-between;">
  <div style="flex-basis: 48%; margin-bottom: 15px;">
    <img src="image.png" alt="Gerenciamento de Ameaças" width="100%">
    <p align="center"><i>Gerenciamento de Ameaças</i></p>
  </div>
  <div style="flex-basis: 48%; margin-bottom: 15px;">
    <img src="image-2.png" alt="Lista de Incidentes" width="100%">
    <p align="center"><i>Lista de Incidentes</i></p>
  </div>
</div>

### Administração e Monitoramento

<div style="display: flex; flex-wrap: wrap; justify-content: space-between;">
  <div style="flex-basis: 48%; margin-bottom: 15px;">
    <img src="image-7.png" alt="Gerenciamento de Usuários" width="100%">
    <p align="center"><i>Gerenciamento de Usuários</i></p>
  </div>
  <div style="flex-basis: 48%; margin-bottom: 15px;">
    <img src="image-8.png" alt="Logs do Sistema" width="100%">
    <p align="center"><i>Logs do Sistema</i></p>
  </div>
</div>

## Requisitos do Sistema

- **.NET 7.0** ou superior
- Sistema operacional Windows, macOS ou Linux
- Acesso de terminal com entrada interativa

## Primeiros Passos

1. Clone o repositório
   ```bash
   git clone https://github.com/seu-usuario/BlackoutGuard.git
   ```

2. Navegue até o diretório do projeto
   ```bash
   cd BlackoutGuard
   ```

3. Compile a aplicação
   ```bash
   dotnet build
   ```

4. Execute a aplicação
   ```bash
   dotnet run
   ```

5. Faça login com as credenciais padrão
   - Usuário: `admin`
   - Senha: `admin123`

## Arquitetura

O BlackoutGuard segue uma arquitetura em camadas:

- **Modelos**: Classes que representam entidades do sistema (User, Alert, Incident, etc.)
- **Serviços**: Lógica de negócios para operações do sistema
- **Interface de Usuário**: Componentes de console para interação
- **Persistência**: Armazenamento baseado em JSON para dados do sistema

## Funções de Usuário

- **Administrador**: Acesso completo ao sistema
- **Analista**: Visualiza e analisa ameaças e incidentes
- **Operador**: Gerencia operações do dia a dia
- **Auditor**: Acesso apenas para visualização e auditoria

## Regras de Negócio

1. Todos os usuários devem se autenticar antes de acessar recursos
2. Alertas críticos devem ser reconhecidos dentro de um prazo configurável
3. Avaliações de vulnerabilidade devem ser realizadas em intervalos regulares
4. Todos os incidentes de segurança devem ser registrados com data e nível de severidade
5. Backups regulares dos dados do sistema devem ser mantidos
6. Relatórios devem ser gerados conforme cronograma estabelecido

## Melhorias Futuras

- Integração com sistemas SCADA
- Previsão de ameaças baseada em aprendizado de máquina
- Aplicativo móvel para alertas em movimento
- Integração com sistemas de segurança física
- Dashboard de análise em tempo real

## Licença

Este projeto está licenciado sob os termos da licença MIT. Veja o arquivo LICENSE para mais detalhes.

---

<div align="center">
  <p>Desenvolvido por Pedro Morais/ Gustavo Vegi - 2025</p>
  <p>
    <a href="https://github.com/seu-usuario">GitHub</a> •
    <a href="https://linkedin.com/in/seu-perfil">LinkedIn</a>
  </p>
</div>