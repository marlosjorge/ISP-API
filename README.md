# ISP-API
Plataforma de Automação de Redes que explora #DevOps #BackEnd #Flask #DesignPattern #PatternCommand #APIRestFULL #BackgroundISP


## Objetivo Geral
Um Backbone de um ISPs (Internet Service Provider) é uma malha de rede tipicamente composta por switches e roteadores operando na camada 2 e 3 do modelo de referência ISO/OSI, que oferece uma gama de serviços de rede como interligação de acessos de clientes, provimento de internet, e relações entre sistemas Autônomos.

Construir uma API para backbones de ISPs (Internet Service Provider) consiste em abstrair a complexidade das formas de administração de redes heterogêneas, possibilitando através de algorítmos efetuar operações em dispositivos e protocolos de rede automatizando ações que são executadas essencialmente por analista e engenheiros de redes.

Através desta disponibilização de uma API (Application Programming Interface), funções e métodos poderão efetuar ações atômicas de manipulação ou consultas no backbone (elementos de rede), abstraindo as especificações e particularidades de fabricante de qualquer dos equipamentos que estejam em operação nesse contexto, resultando numa solução em que algorítmos passarão a tomar ação sobre a pilha de protocolos e funções inerentes aos elementos de rede e caracterísiticas desse backbone, habilitando-o definitivamente a executar operações através de algorítmos.

Ambientes da redes são inevitavelmente complicados e mutáveis, o que traz muitas dificuldades na construção do framework que atuará nessa camada. Portanto, a aplicação de design patterns são de longe bastante aconselháveis. De modo a garantir a organização do projeto e o seu crescimento coeso, padrões globais serão aplicados e deverão ser seguidos pelo projeto inteiro, mas, também, equilibraremos a preocupação com a consistência interna e com a própria filosofia do projeto mais que à obediência cega a padrões e normas.

### Escopo da API

Tipicamente os backbones dos ISPs são compostos por switches e roteadores, e são nestes elementos que a API irá agir, utilizando os próprios recursos disponbilizados para fins de configuração e manutenção, Netconf/Yang, HTTP, são recursos considerados pelo camada de negócio do frameork para possibilitar a iteração, e, de modo a garantir total flexibilidade e compatibilidade, começaremos o projeto pela utilizando <b>Terminal CLI</b> utilizando-se dos recurso do Python pExpect, mas com vistas a agregar demais recursos e tecnologias presentes nestes dispositivos.

### Requisitos funcionais previstos
- Contrução da lógica de negócio para:

	- Gerenciar **Comandos**
		- Aplicar comandos abstraindo diferenças entre dispositivos
		- Gerenciar aplicação de comandos (LOG)
		- Enfileirar sequência de comandos aplicaveis (para assistentes de provisionamento e troubleshootings)
		- Permitir desfazer (Undo)
    
	- Gerenciar **Dispositivos**
		- Efetuar backups
		- Persistir informações atualizadas (inventário)
		- Configurar templates
    
	- Gerenciar **Protocolo de rede aplicados ao backbone**
		- Efetuar descoberta de vizinhanças (CDP, MNDP, EDP, LLDP, etc.);
		- Gerenciar protocolos IGPs (RIP, OSPF, MPLS)
		- Gerenciar protocolos de camada 2 (ERPS, STP, EAPS)
    
 ### Tecnologias utilizadas

- Flask
- Design Patterns

<b>Porque Flask: </b> Diferente do Django, Flask é mais utilizado em pequenas aplicações e microsserviços, como APIs. Embora possa criar grandes projetos com o Flask, é considerado um microframework. Eles são recomendados para aplicações que devem garantir performance. Fornece os recursos e módulos necessários para a criação de uma aplicação. A partir daí, qualquer que seja a necessidade, o desenvolvedor poderá utilizar de bibliotecas externas para incrementar sua aplicação. Isso faz com que o projeto seja o mais simples possível, sem tantos arquivos e módulos desnecessários;

<b>Design Patterns: Command</b>
